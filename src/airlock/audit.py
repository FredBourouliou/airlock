"""Tamper-evident audit log.

Every gateway decision is appended as an entry whose hash chains in the previous
entry's hash. Changing, reordering or dropping any entry breaks the chain, so the
log can be verified after the fact — the same "receipts" idea applied to what the
gateway did and why.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field

GENESIS = "0" * 64


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    ts: float
    direction: str
    tool: str
    decision: str
    rules: list[str]
    reason: str
    prev_hash: str
    hash: str

    def _digest(self) -> str:
        body = {
            "seq": self.seq,
            "ts": self.ts,
            "direction": self.direction,
            "tool": self.tool,
            "decision": self.decision,
            "rules": self.rules,
            "reason": self.reason,
            "prev_hash": self.prev_hash,
        }
        blob = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(blob).hexdigest()


@dataclass
class AuditLog:
    entries: list[AuditEntry] = field(default_factory=list)

    @property
    def _last_hash(self) -> str:
        return self.entries[-1].hash if self.entries else GENESIS

    def append(self, *, direction: str, tool: str, decision: str,
               rules: list[str], reason: str, ts: float | None = None) -> AuditEntry:
        prev = self._last_hash
        draft = AuditEntry(
            seq=len(self.entries),
            ts=time.time() if ts is None else ts,
            direction=direction,
            tool=tool,
            decision=decision,
            rules=list(rules),
            reason=reason,
            prev_hash=prev,
            hash="",
        )
        entry = AuditEntry(**{**asdict(draft), "hash": draft._digest()})
        self.entries.append(entry)
        return entry

    def verify(self) -> bool:
        """Recompute the whole chain; return False on any break."""
        prev = GENESIS
        for i, e in enumerate(self.entries):
            if e.seq != i or e.prev_hash != prev or e.hash != e._digest():
                return False
            prev = e.hash
        return True
