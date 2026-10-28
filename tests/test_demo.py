"""The three demo scenarios: each attack succeeds without Airlock and fails with it."""

import pytest

from airlock.demo import SCENARIOS, run


@pytest.mark.parametrize("sid", list(SCENARIOS))
def test_attack_succeeds_without_airlock(sid):
    outcome, _ = run(sid, with_airlock=False)
    assert outcome.leaks(), f"{sid}: the unguarded agent should have been hijacked"


@pytest.mark.parametrize("sid", list(SCENARIOS))
def test_attack_fails_with_airlock(sid):
    events = []
    outcome, gw = run(sid, with_airlock=True, on_event=events.append)
    assert outcome.leaks() == []
    assert any(e.decision == "block" for e in events)
    assert gw.audit.verify()


def test_payment_is_stopped_outbound_not_inbound():
    # The invoice notice has no trigger words: inbound lets it through, and the
    # outbound payee check is the layer that stops the money.
    events = []
    run("payment", with_airlock=True, on_event=events.append)
    inbound = [e for e in events if e.direction == "inbound" and e.tool == "read_invoice"]
    blocked = [e for e in events if e.decision == "block"]
    assert inbound and inbound[0].decision == "allow"
    assert blocked and blocked[0].direction == "outbound" and blocked[0].tool == "pay_invoice"
    assert ("external-recipient" in {r for r, _ in blocked[0].rules})


def test_legitimate_payment_goes_through():
    from airlock.demo import POLICY
    from airlock.gateway import AirlockGateway
    from airlock.tools import INVOICE_PAGE, build_tools
    paid = []
    gw = AirlockGateway(tools=build_tools(invoice_page=INVOICE_PAGE, paid_sink=paid),
                        policy=POLICY)
    from airlock.demo import agent_payment
    agent_payment(gw.call_tool, lambda _t: None)
    assert len(paid) == 1 and paid[0]["payee"] == "accounts@weavers-co.com"


def test_payment_escalation_reaches_finance():
    events = []
    run("payment", with_airlock=True, on_event=events.append)
    last = events[-1]
    assert last.tool == "send_message" and last.decision == "allow"
