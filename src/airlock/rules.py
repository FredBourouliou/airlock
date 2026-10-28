"""Airlock deterministic inspection engine.

Every tool call an agent wants to make (OUTBOUND) and every piece of content
that reaches the agent (INBOUND) is passed through a set of deterministic rules.
Each rule returns a Finding or nothing; the engine keeps the most severe decision.

This layer uses the standard library only. It is the authoritative layer: a BLOCK
here is final. The optional local-LLM classifier (see classifier.py) can only add
findings, never override a deterministic BLOCK.
"""

from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Optional


# Categories whose characters carry no visible glyph and are only ever used, in
# this context, to break up a trigger word: format chars, and non-spacing /
# enclosing marks left over after NFKC (zalgo-style stacking).
_DROP_CATEGORIES = frozenset({"Cf", "Mn", "Me"})

# Invisible or filler code points that aren't caught by the categories above
# (Hangul fillers are Lo, variation selectors vary): drop them explicitly.
_EXTRA_INVISIBLE = frozenset(
    {0x115F, 0x1160, 0x3164, 0xFFA0}                       # Hangul fillers
    | set(range(0xFE00, 0xFE10))                           # variation selectors
    | set(range(0xE0100, 0xE01F0))                         # variation selectors supp.
    | {0x034F, 0x17B4, 0x17B5, 0x2060}                     # CGJ, Khmer vowel inh., word joiner
)

# A small homoglyph fold: the Cyrillic/Greek look-alikes most used to disguise
# the English trigger words. NOT a full UTS #39 skeleton — that's a documented
# limitation (see README); this covers the common evasion in practice.
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ν": "v", "ο": "o", "ρ": "p",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X",
})


def _canonicalize(s: str, *, fold: bool) -> str:
    """Decode entities to a fixed point, apply NFKC, drop invisible/format/mark
    code points. When `fold` is set, also fold common homoglyphs to ASCII."""
    for _ in range(5):                       # undo double/triple HTML encoding
        decoded = html.unescape(s)
        if decoded == s:
            break
        s = decoded
    s = unicodedata.normalize("NFKC", s)
    s = "".join(
        ch for ch in s
        if ord(ch) not in _EXTRA_INVISIBLE
        and unicodedata.category(ch) not in _DROP_CATEGORIES
    )
    return s.translate(_HOMOGLYPHS) if fold else s


def normalize_text(s: str) -> str:
    """Canonicalise inbound content before matching signatures, so an attacker
    can't evade them with zero-width chars, stacked marks, (double-)encoded HTML
    entities or look-alike letters. Over-normalising here can only cause a false
    *match* (fail-closed), never a missed attack — so homoglyphs ARE folded.

    Note: NOT used for recipient trust — folding a homoglyph domain to ASCII
    would make a spoof look like the trusted domain. Recipients use the strict
    ASCII address grammar instead (see Policy.recipient_is_trusted)."""
    return _canonicalize(s, fold=True)


# A single clean address, restricted to an ASCII dot-atom shape (RFC 5321-ish):
# exactly one '@', no separators, quotes, brackets, '%' or '!' routing chars, and
# no non-ASCII (which would need explicit IDNA validation to be trusted). Anything
# else is rejected outright, so Airlock and the mail tool can't disagree on the
# recipient, and a homoglyph domain can never pass as the org domain.
_SINGLE_ADDR_RE = re.compile(r"^[A-Za-z0-9._+\-]+@([A-Za-z0-9.\-]+)$")


class Direction(IntEnum):
    INBOUND = 0   # tool result / external content on its way to the agent
    OUTBOUND = 1  # a tool call the agent is attempting


class Decision(IntEnum):
    ALLOW = 0
    FLAG = 1
    BLOCK = 2


@dataclass(frozen=True)
class Policy:
    """What the agent is allowed to do, declared up front."""
    org_domain: str = ""
    allowlist_recipients: frozenset[str] = frozenset()
    allowlist_domains: frozenset[str] = frozenset()
    pii_egress_threshold: int = 5  # distinct records with sensitive fields

    def recipient_is_trusted(self, address: str) -> bool:
        # Decide trust on the RAW value, exactly as it will be sent. We must not
        # canonicalize first: stripping an invisible char or NFKC-mapping a
        # compatibility '@' could launder a hostile address into a trusted-looking
        # one while a different string is actually transmitted (parser differential).
        raw = address.strip()
        if not raw.isascii():
            return False
        # Strict grammar: exactly one clean ASCII address. A list, separators, a
        # display name, brackets or '%'/'!' routing chars are all rejected.
        m = _SINGLE_ADDR_RE.match(raw)
        if not m:
            return False
        if raw.lower() in {a.lower() for a in self.allowlist_recipients}:
            return True
        domain = m.group(1).rstrip(".").lower()
        if self.org_domain and domain == self.org_domain.lower():
            return True
        return domain in {d.lower() for d in self.allowlist_domains}


@dataclass
class Event:
    direction: Direction
    tool: str                      # e.g. "read_inbox", "send_message", "read_web"
    text: str = ""                 # raw textual content (inbound body, or call payload)
    recipients: list[str] = field(default_factory=list)   # for send-like OUTBOUND calls
    records: list[dict] = field(default_factory=list)      # structured rows in the payload


@dataclass(frozen=True)
class Finding:
    rule_id: str
    decision: Decision
    reason: str


@dataclass
class Verdict:
    decision: Decision
    findings: list[Finding]

    @property
    def blocked(self) -> bool:
        return self.decision is Decision.BLOCK


# --- sensitive-field detection ------------------------------------------------

_EMAIL_RE = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", re.I)

# Imperative instruction-override phrasings (classic prompt injection).
_OVERRIDE_RE = re.compile(
    r"\b(ignore|disregard|forget)\b.{0,30}\b(previous|above|prior|earlier|all)\b.{0,30}"
    r"\b(instruction|instructions|rules|prompt|context)\b"
    r"|\bnew\s+instructions?\s*:"
    r"|\bsystem\s+(override|prompt)\b"
    r"|\byou\s+are\s+now\b",
    re.I | re.S,
)

# Content that tells the agent to send/forward/export data somewhere.
_EXFIL_VERB_RE = re.compile(
    r"\b(send|forward|email|e-mail|export|upload|transmit|cc|bcc|deliver)\b", re.I
)

# Markers that mimic a system/tool role inside ordinary content.
_ROLE_SPOOF_RE = re.compile(
    r"\[\s*(system|assistant|tool|developer)\b[^\]]*\]"
    r"|<\s*/?\s*(system|assistant|tool)\s*>"
    r"|^\s*(system|tool)\s*:",
    re.I | re.M,
)

_SENSITIVE_FIELDS = ("email", "address", "address1", "postal", "postcode",
                     "zip", "phone", "card", "ssn", "iban")

# A loose card-number shape (13-19 digits, optional spaces/dashes).
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _distinct_cards(text: str) -> set[str]:
    """Card numbers pasted as plain text (Luhn-checked, so ids and timestamps of
    the same length don't count)."""
    found = set()
    for m in _CARD_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            found.add(digits)
    return found


def _record_is_sensitive(obj: object) -> bool:
    """Recursively decide whether a payload carries personal data. Walks nested
    dicts and lists, checks every key name, and scans string values for emails
    and card-number shapes — so nesting the data can't hide it from the check."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = str(k).lower()
            if any(s in key for s in _SENSITIVE_FIELDS):
                return True
            if _record_is_sensitive(v):
                return True
        return False
    if isinstance(obj, (list, tuple, set)):
        return any(_record_is_sensitive(x) for x in obj)
    if isinstance(obj, str):
        return bool(_EMAIL_RE.search(obj) or _CARD_RE.search(obj))
    return False


# --- rules --------------------------------------------------------------------
# A rule takes (event, policy) and returns a Finding or None.

Rule = Callable[[Event, Policy], Optional[Finding]]


def rule_instruction_override(ev: Event, policy: Policy) -> Optional[Finding]:
    if ev.direction is Direction.INBOUND and _OVERRIDE_RE.search(normalize_text(ev.text)):
        return Finding(
            "instruction-override", Decision.BLOCK,
            "Inbound content tries to override the agent's standing instructions.",
        )
    return None


def rule_exfil_instruction(ev: Event, policy: Policy) -> Optional[Finding]:
    """Inbound content that instructs the agent to send data to an outside address."""
    if ev.direction is not Direction.INBOUND:
        return None
    text = normalize_text(ev.text)
    if not _EXFIL_VERB_RE.search(text):
        return None
    outside = [a for a in _EMAIL_RE.findall(text) if not policy.recipient_is_trusted(a)]
    if outside:
        return Finding(
            "exfil-instruction", Decision.BLOCK,
            f"Inbound content asks the agent to send data to an outside address "
            f"({outside[0]}).",
        )
    return None


def rule_role_spoof(ev: Event, policy: Policy) -> Optional[Finding]:
    if ev.direction is Direction.INBOUND and _ROLE_SPOOF_RE.search(normalize_text(ev.text)):
        return Finding(
            "role-spoof", Decision.FLAG,
            "Inbound content impersonates a system/tool role.",
        )
    return None


def rule_external_recipient(ev: Event, policy: Policy) -> Optional[Finding]:
    """Any outbound call that carries recipients off the policy allowlist.

    Fail closed: we check recipients on *every* outbound event that has them,
    whatever the tool is named — a tool called 'notify' or 'webhook' can exfiltrate
    just as well as one called 'send_email'."""
    if ev.direction is not Direction.OUTBOUND:
        return None
    if not ev.recipients:
        return None
    outside = [a for a in ev.recipients if not policy.recipient_is_trusted(a)]
    if outside:
        return Finding(
            "external-recipient", Decision.BLOCK,
            f"Outbound '{ev.tool}' targets an untrusted recipient ({outside[0]}).",
        )
    return None


def rule_pii_volume(ev: Event, policy: Policy) -> Optional[Finding]:
    """Outbound payload carrying sensitive records above the egress threshold —
    as structured records, or as card numbers pasted into free text."""
    if ev.direction is not Direction.OUTBOUND:
        return None
    sensitive = [r for r in ev.records if _record_is_sensitive(r)]
    cards = _distinct_cards(ev.text)
    if len(sensitive) >= policy.pii_egress_threshold:
        return Finding(
            "pii-volume", Decision.BLOCK,
            f"Outbound call carries {len(sensitive)} records with sensitive fields "
            f"(threshold {policy.pii_egress_threshold}).",
        )
    if len(cards) >= policy.pii_egress_threshold:
        return Finding(
            "pii-volume", Decision.BLOCK,
            f"Outbound call carries {len(cards)} card numbers in its text "
            f"(threshold {policy.pii_egress_threshold}).",
        )
    return None


DEFAULT_RULES: tuple[Rule, ...] = (
    rule_instruction_override,
    rule_exfil_instruction,
    rule_role_spoof,
    rule_external_recipient,
    rule_pii_volume,
)


def inspect(ev: Event, policy: Policy, rules: tuple[Rule, ...] = DEFAULT_RULES) -> Verdict:
    """Run every rule, keep all findings, and resolve to the most severe decision."""
    findings = [f for rule in rules if (f := rule(ev, policy)) is not None]
    decision = max((f.decision for f in findings), default=Decision.ALLOW)
    return Verdict(decision=decision, findings=findings)
