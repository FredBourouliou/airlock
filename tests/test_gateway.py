"""End-to-end tests for the interception gateway and the audit log."""

from airlock.audit import AuditLog
from airlock.gateway import AirlockGateway, GatewayEvent
from airlock.rules import Decision, Direction, Finding, Policy
from airlock.tools import CUSTOMERS, INJECTED_EMAIL, build_tools

POLICY = Policy(
    org_domain="alderandash.com",
    allowlist_recipients=frozenset({"owner@alderandash.com", "finance@alderandash.com"}),
    pii_egress_threshold=5,
)


def _gateway(sink=None):
    return AirlockGateway(tools=build_tools(sent_sink=sink), policy=POLICY)


def test_inbound_injection_is_quarantined():
    gw = _gateway()
    result = gw.call_tool("read_inbox")
    # The agent must NOT receive the injected instructions.
    assert "Ignore all previous instructions" not in result.text
    assert "quarantined" in result.text.lower()


def test_benign_inbound_passes_through():
    gw = AirlockGateway(tools=build_tools(inbox=["Hi, invoice attached. Thanks."]),
                        policy=POLICY)
    result = gw.call_tool("read_inbox")
    assert "invoice" in result.text


def test_outbound_send_to_external_is_blocked_and_not_executed():
    sink = []
    gw = _gateway(sink=sink)
    result = gw.call_tool("send_message", {
        "recipients": ["collector@settlement-intake.co"],
        "records": CUSTOMERS,
        "body": "the records you asked for",
    })
    assert "blocked" in result.text.lower()
    assert sink == []  # the send never executed


def test_outbound_send_to_trusted_executes():
    sink = []
    gw = _gateway(sink=sink)
    result = gw.call_tool("send_message", {
        "recipients": ["owner@alderandash.com"],
        "body": "Weekly total: 7 orders, $597.43.",
    })
    assert "sent" in result.text.lower()
    assert len(sink) == 1


def test_pii_volume_send_even_to_trusted_is_blocked():
    sink = []
    gw = _gateway(sink=sink)
    result = gw.call_tool("send_message", {
        "recipients": ["owner@alderandash.com"],
        "records": CUSTOMERS,
    })
    assert "blocked" in result.text.lower()
    assert sink == []


def test_events_are_emitted_to_subscribers():
    gw = _gateway()
    events: list[GatewayEvent] = []
    gw.subscribe(events.append)
    gw.call_tool("read_inbox")
    assert events
    assert events[-1].direction == "inbound"
    assert events[-1].decision == "block"
    assert events[-1].quarantined is True


def test_classifier_can_escalate_but_not_downgrade():
    # A benign-looking inbound that deterministic rules allow, but the classifier
    # flags as malicious.
    def classifier(text: str):
        if "weather" in text.lower():
            return Finding("llm-classifier", Decision.BLOCK, "Model: manipulation attempt.")
        return None

    gw = AirlockGateway(tools=build_tools(web="The weather is nice today."),
                        policy=POLICY, classifier=classifier)
    result = gw.call_tool("read_web")
    assert "quarantined" in result.text.lower()


# --- audit log ---------------------------------------------------------------

def test_audit_chain_verifies():
    gw = _gateway()
    gw.call_tool("read_inbox")
    gw.call_tool("send_message", {"recipients": ["owner@alderandash.com"], "body": "ok"})
    assert len(gw.audit.entries) >= 2
    assert gw.audit.verify()


def test_audit_tampering_breaks_the_chain():
    log = AuditLog()
    log.append(direction="inbound", tool="read_inbox", decision="block",
               rules=["instruction-override"], reason="x")
    log.append(direction="outbound", tool="send_message", decision="allow",
               rules=[], reason="")
    assert log.verify()
    # Tamper with the first entry's decision.
    import dataclasses
    log.entries[0] = dataclasses.replace(log.entries[0], decision="allow")
    assert not log.verify()
