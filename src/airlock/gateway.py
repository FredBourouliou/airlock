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

import json
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from airlock.audit import AuditLog
from airlock.rules import (
    _EMAIL_RE,
    _record_is_sensitive,
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


# --- comprehensive extraction -------------------------------------------------
# A guard must not trust the agent to put data in the keys it expects. We walk
# the whole argument/result structure, not a chosen few keys.

# Keys whose string values are recipients: those are checked RAW by the strict
# grammar, so a weird or multi-address value fails closed (untrusted).
_RECIPIENT_KEYS = frozenset({
    "recipients", "recipient", "to", "cc", "bcc", "dest", "destination",
    "mailto", "email", "emails", "send_to", "sendto",
})


def _walk_strings(obj: object):
    """Every piece of text in a structure: dict keys as well as values, and
    non-string scalars as their str() — an injection can ride in a key too."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _walk_strings(v)
    elif isinstance(obj, (list, tuple, set)):
        for x in obj:
            yield from _walk_strings(x)
    elif isinstance(obj, str):
        yield obj
    elif obj is not None:
        yield str(obj)


def _candidate_recipients(obj: object) -> list[str]:
    """Recipient candidates for the strict allowlist check. Anything under a
    recipient-bearing key — string values, dict keys, non-string scalars — is
    passed through RAW, so a multi-address, malformed or non-string value fails
    closed. Addresses embedded anywhere else (values or keys) are added as extra
    candidates via the regex, and so is any address visible in the serialized call."""
    cands: list[str] = []

    def walk(o: object, in_dest: bool) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                key = str(k)
                if in_dest:
                    cands.append(key)
                else:
                    cands.extend(_EMAIL_RE.findall(key))
                walk(v, in_dest or key.strip().lower() in _RECIPIENT_KEYS)
        elif isinstance(o, (list, tuple, set)):
            for x in o:
                walk(x, in_dest)
        elif isinstance(o, str):
            if in_dest:
                cands.append(o)
            else:
                cands.extend(_EMAIL_RE.findall(o))
        elif in_dest and o is not None:
            cands.append(str(o))   # a non-string recipient can't be validated

    walk(obj, False)
    cands.extend(_EMAIL_RE.findall(json.dumps(obj, default=str, ensure_ascii=False)))
    return cands


def _collect_records(obj: object) -> list[dict]:
    """Record units for the PII-volume rule: the innermost sensitive dicts at any
    depth — list elements and dict values alike, so `{"c1": {...}, "c2": {...}}`
    counts two records. A dict that only wraps sensitive dicts isn't counted
    itself, so nesting one record deeply doesn't inflate the count. The call's
    own top-level arguments are never a record."""
    out: list[dict] = []

    def walk(o: object) -> bool:
        """Walk `o`; return True if it is or contains a counted record."""
        if isinstance(o, dict):
            inner = [walk(v) for v in o.values()]
            if any(inner):
                return True
            if _record_is_sensitive(o):
                out.append(o)
                return True
            return False
        if isinstance(o, (list, tuple, set)):
            return any([walk(x) for x in o])
        return False

    for v in (obj.values() if isinstance(obj, dict) else [obj]):
        walk(v)
    return out


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

        # 1) OUTBOUND: inspect the whole call, not the keys we happen to expect.
        out_ev = Event(
            direction=Direction.OUTBOUND,
            tool=name,
            text=json.dumps(args, default=str, ensure_ascii=False),
            recipients=_candidate_recipients(args),
            records=_collect_records(args),
        )
        out_verdict = inspect(out_ev, self.policy)
        if out_verdict.blocked:
            self._emit(Direction.OUTBOUND, name, out_verdict, quarantined=True)
            reason = out_verdict.findings[0].reason
            return ToolResult(text=f"[Airlock blocked this call: {reason}]")
        self._emit(Direction.OUTBOUND, name, out_verdict, quarantined=False)

        # 2) Execute the real tool.
        result = self.tools[name](args)

        # 3) INBOUND: inspect what comes back — including string values hidden in
        # records, where an injection could otherwise ride in unscanned.
        record_text = "\n".join(_walk_strings(result.records))
        scanned = result.text if not record_text else f"{result.text}\n{record_text}"
        in_ev = Event(direction=Direction.INBOUND, tool=name,
                      text=scanned, records=result.records)
        in_verdict = inspect(in_ev, self.policy)
        in_verdict = self._apply_classifier(in_verdict, scanned)
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
