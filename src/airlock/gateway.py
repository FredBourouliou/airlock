"""The Airlock gateway.

Every tool call an agent makes passes through here twice:

  OUTBOUND — before the call runs, its arguments (recipients, records, body) are
             inspected. A BLOCK means the call never executes.
  INBOUND  — before the result reaches the agent, its content is inspected. A
             BLOCK means the content is quarantined and the agent gets a neutral
             placeholder instead, so it keeps working, uncontaminated.

Each decision is emitted to any subscribers (the SOC console) and appended to the
tamper-evident audit log. The deterministic rule engine is authoritative; an
optional local-LLM classifier can only raise the severity of inbound content,
never lower a deterministic block.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from airlock.audit import AuditLog
from airlock.rules import (
    Decision,
    Direction,
    Event,
    Finding,
    Policy,
    Verdict,
    inspect,
)
from airlock.tools import Tool, ToolResult

# A classifier takes inbound text and may return one extra Finding.
Classifier = Callable[[str], Optional[Finding]]


@dataclass
class GatewayEvent:
    seq: int
    ts: float
    direction: str          # "inbound" / "outbound"
    tool: str
    decision: str           # "allow" / "flag" / "block"
    rules: list[tuple[str, str]]  # (rule_id, reason)
    summary: str
    quarantined: bool


_PLACEHOLDER = "[Airlock: content quarantined — suspected prompt injection or data exfiltration]"


@dataclass
class AirlockGateway:
    tools: dict[str, Tool]
    policy: Policy
    classifier: Optional[Classifier] = None
    audit: AuditLog = field(default_factory=AuditLog)
    subscribers: list[Callable[[GatewayEvent], None]] = field(default_factory=list)
    _seq: int = 0

    def subscribe(self, fn: Callable[[GatewayEvent], None]) -> None:
        self.subscribers.append(fn)

    # -- event plumbing --------------------------------------------------------

    def _emit(self, direction: Direction, tool: str, verdict: Verdict,
              quarantined: bool) -> GatewayEvent:
        dname = "inbound" if direction is Direction.INBOUND else "outbound"
        decision = verdict.decision.name.lower()
        rules = [(f.rule_id, f.reason) for f in verdict.findings]
        summary = (f"{decision.upper()} — " +
                   (verdict.findings[0].reason if verdict.findings else "no finding"))
        ev = GatewayEvent(
            seq=self._seq, ts=time.time(), direction=dname, tool=tool,
            decision=decision, rules=rules, summary=summary, quarantined=quarantined,
        )
        self._seq += 1
        self.audit.append(
            direction=dname, tool=tool, decision=decision,
            rules=[r for r, _ in rules],
            reason=(verdict.findings[0].reason if verdict.findings else ""),
            ts=ev.ts,
        )
        for fn in self.subscribers:
            fn(ev)
        return ev

    # -- the interception path -------------------------------------------------

    def call_tool(self, name: str, args: Optional[dict] = None) -> ToolResult:
        args = args or {}
        if name not in self.tools:
            raise KeyError(f"unknown tool: {name}")

        # 1) OUTBOUND: inspect the call the agent wants to make.
        out_ev = Event(
            direction=Direction.OUTBOUND,
            tool=name,
            text=args.get("body", ""),
            recipients=list(args.get("recipients", [])),
            records=list(args.get("records", [])),
        )
        out_verdict = inspect(out_ev, self.policy)
        if out_verdict.blocked:
            self._emit(Direction.OUTBOUND, name, out_verdict, quarantined=True)
            reason = out_verdict.findings[0].reason
            return ToolResult(text=f"[Airlock blocked this call: {reason}]")
        self._emit(Direction.OUTBOUND, name, out_verdict, quarantined=False)

        # 2) Execute the real tool.
        result = self.tools[name](args)

        # 3) INBOUND: inspect what comes back before the agent sees it.
        in_ev = Event(direction=Direction.INBOUND, tool=name,
                      text=result.text, records=result.records)
        in_verdict = inspect(in_ev, self.policy)
        in_verdict = self._apply_classifier(in_verdict, result.text)
        if in_verdict.blocked:
            self._emit(Direction.INBOUND, name, in_verdict, quarantined=True)
            return ToolResult(text=_PLACEHOLDER)
        self._emit(Direction.INBOUND, name, in_verdict, quarantined=False)
        return result

    def _apply_classifier(self, verdict: Verdict, text: str) -> Verdict:
        """Let the optional local-LLM classifier add one finding. It can raise the
        severity but never lower a deterministic block."""
        if self.classifier is None or verdict.blocked or not text.strip():
            return verdict
        extra = self.classifier(text)
        if extra is None:
            return verdict
        findings = verdict.findings + [extra]
        decision = max(f.decision for f in findings)
        return Verdict(decision=decision, findings=findings)
