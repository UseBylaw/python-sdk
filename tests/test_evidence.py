# Bylaw ALCV — Evidence layer tests (Phase 2)

from __future__ import annotations

import json

import pytest
import respx
from httpx import ConnectError, Response

import bylaw_python as bylaw
from bylaw_python import VaultConfig
from bylaw_python.enforce import enforce
from bylaw_python.evidence import set_session_store
from bylaw_python.exceptions import EvidenceBlockedError
from bylaw_python.jsonpath import extract_path
from bylaw_python.manifest import EvidenceRule, load_manifest
from bylaw_python.session_store import InMemorySessionStore


def _config(mode: str = "observe") -> VaultConfig:
    return VaultConfig(
        vault_url="https://vault.test",
        vault_api_key="test-api-key",
        vault_timeout=5.0,
        verify_jwt=False,
        agent_id="test-agent",
        session_id="sess_1",
        max_retries=0,
        evidence_mode=mode,
    )


@pytest.fixture(autouse=True)
def fresh_session_store():
    set_session_store(InMemorySessionStore())
    yield
    set_session_store(None)


def _facts_side_effect(request) -> Response:
    """Echo a deterministic fact id per registered field."""
    body = json.loads(request.content)
    field = body["field"]
    return Response(201, json={"status": "registered", "fact": {"id": f"fact_{field}", "field": field}})


SOURCE_RULE = EvidenceRule(
    kind="source",
    customer_id="args.customer_id",
    fields={"date_of_birth": "result.dob", "risk_profile": "result.risk"},
    source_type="profile",
)
ACTION_RULE = EvidenceRule(
    kind="action",
    action_type="generate_share_recommendation",
    customer_id="args.customer_id",
    requires=("date_of_birth", "risk_profile"),
)


# ---------------------------------------------------------------------------
# Unit: jsonpath + session store + manifest parsing
# ---------------------------------------------------------------------------

def test_extract_path_dotted_and_indexed():
    root = {"args": {"customer_id": "c1"}, "result": {"items": [{"dob": "1988-05-12"}]}}
    assert extract_path(root, "args.customer_id") == "c1"
    assert extract_path(root, "result.items[0].dob") == "1988-05-12"
    assert extract_path(root, "result.items[5].dob") is None
    assert extract_path(root, "missing.path") is None


def test_session_store_isolation_and_obligations():
    s = InMemorySessionStore()
    s.put_fact("sess_1", "c1", "date_of_birth", "fact_a")
    s.put_fact("sess_2", "c1", "date_of_birth", "fact_b")
    assert s.get_fact("sess_1", "c1", "date_of_birth") == "fact_a"
    assert s.fact_ids("sess_2", "c1") == ["fact_b"]
    assert s.fact_ids("sess_1", "c1", ["date_of_birth"]) == ["fact_a"]
    s.add_obligations("sess_1", "c1", ["do_not_update_profile"])
    assert "do_not_update_profile" in s.obligations("sess_1", "c1")


def test_manifest_parses_evidence_block():
    m = load_manifest({"enforce": [
        {"tool": "get_*", "evidence": {"kind": "source", "source_type": "profile",
                                       "customer_id": "args.customer_id", "fields": {"dob": "result.dob"}}},
        {"tool": "recommend", "evidence": {"kind": "action", "action_type": "x", "requires": ["dob"]}},
    ]})
    assert m.rules[0].evidence.kind == "source"
    assert m.rules[0].evidence.fields == {"dob": "result.dob"}
    assert m.rules[1].evidence.action_type == "x"
    assert m.rules[1].evidence.requires == ("dob",)


def test_manifest_normalizes_and_validates_evidence_kind():
    m = load_manifest({"enforce": [
        {"tool": "get_*", "evidence": {"kind": "SOURCE", "fields": {"dob": "result.dob"}}},
    ]})
    assert m.rules[0].evidence.kind == "source"

    with pytest.raises(ValueError, match="evidence kind"):
        load_manifest({"enforce": [
            {"tool": "get_*", "evidence": {"fields": {"dob": "result.dob"}}},
        ]})


def test_evidence_mode_is_normalized_and_validated():
    assert _config("ENFORCE").evidence_mode == "enforce"

    with pytest.raises(ValueError, match="evidence_mode"):
        _config("enforced")


# ---------------------------------------------------------------------------
# Source observation + action guard (the core flow)
# ---------------------------------------------------------------------------

@respx.mock
def test_source_auto_registers_then_action_attaches_facts():
    bylaw.configure(_config("observe"))
    facts = respx.post("https://vault.test/v1/evidence/facts").mock(side_effect=_facts_side_effect)
    check = respx.post("https://vault.test/v1/evidence/check-action").mock(
        return_value=Response(200, json={"decision": "allow", "reason": "ok", "action_type": "generate_share_recommendation"})
    )

    @enforce(tool_name="get_profile", evidence=SOURCE_RULE)
    def get_profile(customer_id: str):
        return {"dob": "1988-05-12", "risk": "balanced"}

    @enforce(tool_name="recommend", evidence=ACTION_RULE)
    def recommend(customer_id: str):
        return "recommendation"

    assert get_profile(customer_id="cust_42") == {"dob": "1988-05-12", "risk": "balanced"}
    assert facts.call_count == 2  # both mapped fields registered

    assert recommend(customer_id="cust_42") == "recommendation"
    body = json.loads(check.calls.last.request.content)
    sent = {f["fact_id"] for f in body["facts"]}
    assert sent == {"fact_date_of_birth", "fact_risk_profile"}
    assert body["action_type"] == "generate_share_recommendation"
    assert body["mode"] == "observe"


@respx.mock
def test_observe_mode_does_not_block_on_deny():
    bylaw.configure(_config("observe"))
    respx.post("https://vault.test/v1/evidence/check-action").mock(
        return_value=Response(200, json={"decision": "deny", "reason": "missing required fact", "action_type": "x"})
    )
    ran = {"v": False}

    @enforce(tool_name="recommend", evidence=ACTION_RULE)
    def recommend(customer_id: str):
        ran["v"] = True
        return "ok"

    # Observe mode records but never blocks — the agent proceeds.
    assert recommend(customer_id="cust_42") == "ok"
    assert ran["v"] is True


@respx.mock
def test_observe_mode_does_not_block_on_transport_failure():
    bylaw.configure(_config("observe"))
    respx.post("https://vault.test/v1/evidence/check-action").mock(
        side_effect=ConnectError("connection refused")
    )
    ran = {"v": False}

    @enforce(tool_name="recommend", evidence=ACTION_RULE)
    def recommend(customer_id: str):
        ran["v"] = True
        return "ok"

    assert recommend(customer_id="cust_42") == "ok"
    assert ran["v"] is True


@respx.mock
def test_context_policy_with_evidence_still_requests_clearance():
    bylaw.configure(_config("observe"))
    clearance = respx.post("https://vault.test/request-clearance").mock(
        return_value=Response(200, json={
            "status": "approved", "decision_status": "approved", "reason": "ok", "request_id": "req-1",
        })
    )
    respx.post("https://vault.test/v1/evidence/check-action").mock(
        return_value=Response(200, json={"decision": "allow", "reason": "ok", "action_type": "x"})
    )

    @enforce(tool_name="recommend", context={"policy_id": "ctx-policy"}, evidence=ACTION_RULE)
    def recommend(customer_id: str):
        return "ok"

    assert recommend(customer_id="cust_42") == "ok"
    body = json.loads(clearance.calls.last.request.content)
    assert body["context"]["policy_id"] == "ctx-policy"


@respx.mock
def test_enforce_mode_blocks_on_deny():
    bylaw.configure(_config("enforce"))
    respx.post("https://vault.test/v1/evidence/check-action").mock(
        return_value=Response(200, json={"decision": "deny", "reason": "missing required fact",
                                          "receipt_id": "r1", "action_type": "x"})
    )
    ran = {"v": False}

    @enforce(tool_name="recommend", evidence=ACTION_RULE)
    def recommend(customer_id: str):
        ran["v"] = True
        return "ok"

    with pytest.raises(EvidenceBlockedError) as exc:
        recommend(customer_id="cust_42")
    assert exc.value.decision == "deny"
    assert exc.value.receipt_id == "r1"
    assert ran["v"] is False  # blocked before the tool body ran


@respx.mock
def test_action_guard_skips_when_customer_is_unresolved():
    bylaw.configure(_config("observe"))
    check = respx.post("https://vault.test/v1/evidence/check-action").mock(
        return_value=Response(200, json={"decision": "deny", "reason": "missing customer", "action_type": "x"})
    )
    rule = EvidenceRule(kind="action", action_type="x")

    @enforce(tool_name="recommend", evidence=rule)
    def recommend():
        return "ok"

    assert recommend() == "ok"
    assert not check.called


@respx.mock
def test_evidence_only_wrapper_clears_nested_current_clearance():
    bylaw.configure(_config("off"))
    respx.post("https://vault.test/request-clearance").mock(
        return_value=Response(200, json={
            "status": "approved", "decision_status": "approved", "token": "outer-token",
            "reason": "ok", "request_id": "req-1",
        })
    )

    @enforce(tool_name="inner", evidence=SOURCE_RULE)
    def inner(customer_id: str):
        return bylaw.current_token()

    @enforce(tool_name="outer", policy_id="policy-x")
    def outer():
        before = bylaw.current_token()
        during = inner(customer_id="cust_42")
        after = bylaw.current_token()
        return before, during, after

    assert outer() == ("outer-token", None, "outer-token")


@respx.mock
def test_obligations_carried_into_session_store():
    bylaw.configure(_config("observe"))
    check = respx.post("https://vault.test/v1/evidence/check-action").mock(
        side_effect=[
            Response(200, json={
                "decision": "allow_with_obligations", "reason": "chat session only", "action_type": "x",
                "obligations": [{"code": "do_not_update_profile", "field": "date_of_birth"}],
            }),
            Response(200, json={"decision": "allow", "reason": "ok", "action_type": "x"}),
        ]
    )

    @enforce(tool_name="recommend", evidence=ACTION_RULE)
    def recommend(customer_id: str):
        return "ok"

    recommend(customer_id="cust_42")
    recommend(customer_id="cust_42")
    from bylaw_python.evidence import _get_store
    assert "do_not_update_profile" in _get_store().obligations("sess_1", "cust_42")
    body = json.loads(check.calls.last.request.content)
    assert body["obligations"] == ["do_not_update_profile"]


@respx.mock
def test_off_mode_skips_evidence_entirely():
    bylaw.configure(_config("off"))
    facts = respx.post("https://vault.test/v1/evidence/facts").mock(side_effect=_facts_side_effect)
    check = respx.post("https://vault.test/v1/evidence/check-action").mock(
        return_value=Response(200, json={"decision": "allow", "reason": "ok", "action_type": "x"})
    )

    @enforce(tool_name="get_profile", evidence=SOURCE_RULE)
    def get_profile(customer_id: str):
        return {"dob": "1988-05-12", "risk": "balanced"}

    @enforce(tool_name="recommend", evidence=ACTION_RULE)
    def recommend(customer_id: str):
        return "ok"

    get_profile(customer_id="cust_42")
    recommend(customer_id="cust_42")
    assert not facts.called
    assert not check.called


def test_unsupported_session_backend_is_rejected():
    set_session_store(None)
    cfg = _config("observe").model_copy(update={"evidence_session_backend": "redis"})

    with pytest.raises(ValueError, match="Unsupported evidence_session_backend"):
        bylaw.configure(cfg)


def test_configure_resets_default_session_store():
    from bylaw_python.evidence import _get_store

    set_session_store(None)
    bylaw.configure(_config("observe"))
    _get_store().put_fact("sess_1", "cust_42", "date_of_birth", "fact_old")

    bylaw.configure(_config("observe"))

    assert _get_store().fact_ids("sess_1", "cust_42") == []


@respx.mock
def test_evidence_session_context_overrides_customer():
    bylaw.configure(_config("observe"))
    facts = respx.post("https://vault.test/v1/evidence/facts").mock(side_effect=_facts_side_effect)
    clearance = respx.post("https://vault.test/request-clearance").mock(
        return_value=Response(200, json={
            "status": "approved", "decision_status": "approved", "reason": "ok", "request_id": "req-1",
        })
    )
    check = respx.post("https://vault.test/v1/evidence/check-action").mock(
        return_value=Response(200, json={"decision": "allow", "reason": "ok", "action_type": "x"})
    )

    # Source/action rules that do NOT carry customer in args; rely on context.
    src = EvidenceRule(kind="source", fields={"date_of_birth": "result.dob"}, source_type="profile")
    act = EvidenceRule(kind="action", action_type="x", requires=("date_of_birth",))

    @enforce(tool_name="get_profile", evidence=src)
    def get_profile():
        return {"dob": "1988-05-12"}

    @enforce(tool_name="recommend", policy_id="policy-x", evidence=act)
    def recommend():
        return "ok"

    with bylaw.evidence_session(session_id="sess_X", customer_id="cust_ctx"):
        get_profile()
        recommend()

    body = json.loads(check.calls.last.request.content)
    assert body["session_id"] == "sess_X"
    assert {f["fact_id"] for f in body["facts"]} == {"fact_date_of_birth"}
    clearance_body = json.loads(clearance.calls.last.request.content)
    assert clearance_body["session_id"] == "sess_X"


# ---------------------------------------------------------------------------
# Direct client methods
# ---------------------------------------------------------------------------

@respx.mock
def test_client_evidence_methods():
    from bylaw_python import BylawClient, CheckActionRequest, RegisterFactRequest

    client = BylawClient(_config())
    respx.post("https://vault.test/v1/evidence/facts").mock(
        return_value=Response(201, json={"fact": {"id": "fact_1", "field": "dob"}})
    )
    respx.post("https://vault.test/v1/evidence/check-action").mock(
        return_value=Response(200, json={"decision": "allow", "reason": "ok"})
    )
    respx.get("https://vault.test/v1/evidence/graph").mock(
        return_value=Response(200, json={"customer_id_hash": "sha256:x", "facts": [{"fact_id": "fact_1", "field": "dob"}]})
    )

    fact = client.register_fact(RegisterFactRequest(customer_id="c1", field="dob", value="1988-05-12", source_type="profile"))
    assert fact.id == "fact_1"
    res = client.check_action(CheckActionRequest(customer_id="c1", action_type="x"))
    assert res.is_allowed
    graph = client.fetch_evidence_graph("c1", "sess_1")
    assert len(graph.facts) == 1 and graph.facts[0].fact_id == "fact_1"
    client.close()
