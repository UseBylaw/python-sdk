# Bylaw ALCV — Output grounding tests (Phase 4)

from __future__ import annotations

import json
import logging

import pytest
import respx
from httpx import Response

import bylaw_python as bylaw
from bylaw_python import VaultConfig, guard_output
from bylaw_python.enforce import _get_default_client as get_default_client
from bylaw_python.enforce import enforce
from bylaw_python.evidence import set_session_store
from bylaw_python.exceptions import EvidenceBlockedError, EvidenceError
from bylaw_python.manifest import EvidenceRule, load_manifest
from bylaw_python.session_store import InMemorySessionStore


def _config(output_mode: str = "observe") -> VaultConfig:
    return VaultConfig(
        vault_url="https://vault.test",
        vault_api_key="test-api-key",
        vault_timeout=5.0,
        verify_jwt=False,
        agent_id="test-agent",
        session_id="sess_1",
        max_retries=0,
        evidence_mode="off",  # actions off — output mode is independent
        evidence_output_mode=output_mode,
    )


@pytest.fixture(autouse=True)
def fresh_session_store():
    set_session_store(InMemorySessionStore())
    yield
    set_session_store(None)


OUTPUT_RULE = EvidenceRule(
    kind="output",
    action_type="send_financial_response",
    customer_id="args.customer_id",
    response_text="result.message",
)


def _allow(_request) -> Response:
    return Response(200, json={"decision": "allow", "reason": "numbers grounded", "action_type": "send_financial_response"})


def _allow_with_obligations(_request) -> Response:
    return Response(200, json={
        "decision": "allow_with_obligations",
        "reason": "numbers grounded with obligations",
        "action_type": "send_financial_response",
        "obligations": [{"code": "cite_sources", "field": "response_text"}],
    })


def _deny(_request) -> Response:
    return Response(200, json={"decision": "deny", "reason": "number not grounded", "receipt_id": "r_out"})


# ---------------------------------------------------------------------------
# Manifest parsing
# ---------------------------------------------------------------------------

def test_manifest_parses_output_kind():
    m = load_manifest(
        {
            "enforce": [
                {
                    "tool": "send_*",
                    "evidence": {
                        "kind": "output",
                        "action_type": "send_financial_response",
                        "customer_id": "args.customer_id",
                        "response_text": "result.message",
                        "claims_path": "result.claims",
                    },
                }
            ]
        }
    )
    ev = m.match("send_reply").evidence
    assert ev.kind == "output"
    assert ev.response_text == "result.message"
    assert ev.claims_path == "result.claims"


# ---------------------------------------------------------------------------
# Mode behaviour
# ---------------------------------------------------------------------------

@respx.mock
def test_off_mode_skips_check_output():
    bylaw.configure(_config("off"))
    route = respx.post("https://vault.test/v1/evidence/check-output").mock(side_effect=_deny)

    @enforce(tool_name="send_reply", evidence=OUTPUT_RULE)
    def send_reply(customer_id: str):
        return {"message": "Your balance is up 12%."}

    assert send_reply(customer_id="cust_1")["message"].startswith("Your balance")
    assert not route.called


@respx.mock
def test_observe_mode_records_but_never_blocks():
    bylaw.configure(_config("observe"))
    route = respx.post("https://vault.test/v1/evidence/check-output").mock(side_effect=_deny)

    @enforce(tool_name="send_reply", evidence=OUTPUT_RULE)
    def send_reply(customer_id: str):
        return {"message": "You should move $52,000 into bonds."}

    # Even on a deny, observe returns the result and does not raise.
    out = send_reply(customer_id="cust_1")
    assert out["message"].startswith("You should move")
    assert route.called
    body = json.loads(route.calls.last.request.content)
    assert body["response_text"] == "You should move $52,000 into bonds."
    assert body["mode"] == "observe"


@respx.mock
def test_enforce_mode_blocks_ungrounded_number():
    bylaw.configure(_config("enforce"))
    respx.post("https://vault.test/v1/evidence/check-output").mock(side_effect=_deny)

    @enforce(tool_name="send_reply", evidence=OUTPUT_RULE)
    def send_reply(customer_id: str):
        return {"message": "You should move $52,000 into bonds."}

    with pytest.raises(EvidenceBlockedError):
        send_reply(customer_id="cust_1")


@respx.mock
def test_enforce_mode_allows_grounded_number():
    bylaw.configure(_config("enforce"))
    respx.post("https://vault.test/v1/evidence/check-output").mock(side_effect=_allow)

    @enforce(tool_name="send_reply", evidence=OUTPUT_RULE)
    def send_reply(customer_id: str):
        return {"message": "Your balance is up 12% this quarter."}

    assert send_reply(customer_id="cust_1")["message"].startswith("Your balance")


@respx.mock
def test_enforce_mode_blocks_empty_extracted_response_text():
    bylaw.configure(_config("enforce"))
    route = respx.post("https://vault.test/v1/evidence/check-output").mock(side_effect=_allow)
    bad_rule = EvidenceRule(
        kind="output",
        action_type="send_financial_response",
        customer_id="args.customer_id",
        response_text="result.missing",
    )

    @enforce(tool_name="send_reply", evidence=bad_rule)
    def send_reply(customer_id: str):
        return {"message": "Your balance is up 12% this quarter."}

    with pytest.raises(EvidenceError, match="non-empty response text"):
        send_reply(customer_id="cust_1")
    assert not route.called


@respx.mock
def test_observe_mode_warns_on_empty_extracted_response_text(caplog):
    bylaw.configure(_config("observe"))
    route = respx.post("https://vault.test/v1/evidence/check-output").mock(side_effect=_allow)
    bad_rule = EvidenceRule(
        kind="output",
        action_type="send_financial_response",
        customer_id="args.customer_id",
        response_text="result.missing",
    )
    caplog.set_level(logging.WARNING, logger="bylaw.evidence")

    @enforce(tool_name="send_reply", evidence=bad_rule)
    def send_reply(customer_id: str):
        return {"message": "Your balance is up 12% this quarter."}

    assert send_reply(customer_id="cust_1")["message"].startswith("Your balance")
    assert not route.called
    assert "evidence: empty response text for output guard; skipping" in caplog.text


def test_enforce_mode_blocks_missing_customer_id():
    bylaw.configure(_config("enforce"))
    bad_rule = EvidenceRule(
        kind="output",
        action_type="send_financial_response",
        response_text="result.message",
    )

    @enforce(tool_name="send_reply", evidence=bad_rule)
    def send_reply():
        return {"message": "Your balance is up 12% this quarter."}

    with pytest.raises(EvidenceError, match="customer id"):
        send_reply()


def test_observe_mode_continues_on_check_output_transport_failure(monkeypatch):
    client = bylaw.configure(_config("observe"))

    def fail_check_output(_request):
        raise bylaw.VaultConnectionError("vault down")

    monkeypatch.setattr(client, "check_output", fail_check_output)

    @enforce(tool_name="send_reply", evidence=OUTPUT_RULE)
    def send_reply(customer_id: str):
        return {"message": "Your balance is up 12% this quarter."}

    assert send_reply(customer_id="cust_1")["message"].startswith("Your balance")


@pytest.mark.asyncio
async def test_observe_mode_continues_on_async_check_output_transport_failure(monkeypatch):
    client = bylaw.configure(_config("observe"))

    async def fail_check_output(_request):
        raise bylaw.VaultConnectionError("vault down")

    monkeypatch.setattr(client, "acheck_output", fail_check_output)

    @enforce(tool_name="send_reply", evidence=OUTPUT_RULE)
    async def send_reply(customer_id: str):
        return {"message": "Your balance is up 12% this quarter."}

    out = await send_reply(customer_id="cust_1")
    assert out["message"].startswith("Your balance")


@respx.mock
def test_output_obligations_carried_into_session_store():
    bylaw.configure(_config("observe"))
    respx.post("https://vault.test/v1/evidence/check-output").mock(side_effect=_allow_with_obligations)

    @enforce(tool_name="send_reply", evidence=OUTPUT_RULE)
    def send_reply(customer_id: str):
        return {"message": "Your balance is up 12% this quarter."}

    send_reply(customer_id="cust_1")
    from bylaw_python.evidence import _get_store
    assert "cite_sources" in _get_store().obligations("sess_1", "cust_1")


# ---------------------------------------------------------------------------
# Public helper for raw LLM text (no wrapped tool)
# ---------------------------------------------------------------------------

@respx.mock
def test_public_guard_output_helper_observe():
    bylaw.configure(_config("observe"))
    route = respx.post("https://vault.test/v1/evidence/check-output").mock(side_effect=_deny)
    client = get_default_client()
    res = guard_output(client, "Your projected return is 9.4%.", customer_id="cust_9")
    assert res is not None and res.decision == "deny"
    assert route.called
    body = json.loads(route.calls.last.request.content)
    assert body["customer_id"] == "cust_9"


@respx.mock
def test_public_guard_output_helper_enforce_blocks():
    bylaw.configure(_config("enforce"))
    respx.post("https://vault.test/v1/evidence/check-output").mock(side_effect=_deny)
    client = get_default_client()
    with pytest.raises(EvidenceBlockedError):
        guard_output(client, "Your projected return is 9.4%.", customer_id="cust_9")


@respx.mock
def test_off_mode_helper_returns_none_without_calling():
    bylaw.configure(_config("off"))
    route = respx.post("https://vault.test/v1/evidence/check-output").mock(side_effect=_deny)
    client = get_default_client()
    assert guard_output(client, "Your return is 9.4%.", customer_id="cust_9") is None
    assert not route.called
