# Bylaw ALCV — Evidence layer Part A tests (inferred facts + arg-threshold context)

from __future__ import annotations

import json

import pytest
import respx
from httpx import Response

import bylaw_python as bylaw
from bylaw_python import CheckActionRequest, RegisterFactRequest, VaultConfig
from bylaw_python.evidence import _fact_request, _threshold_context, set_session_store
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


# ---- model serialization ----------------------------------------------------

def test_register_fact_request_serializes_is_inferred():
    req = RegisterFactRequest(
        customer_id="c1", field="date_of_birth", source_type="long_term_memory",
        value="1988-05-12", is_inferred=True,
    )
    body = json.loads(req.model_dump_json())
    assert body["is_inferred"] is True


def test_register_fact_request_defaults_observed():
    req = RegisterFactRequest(customer_id="c1", field="x", source_type="chat")
    assert json.loads(req.model_dump_json())["is_inferred"] is False


def test_check_action_request_serializes_context():
    req = CheckActionRequest(action_type="run_experiment", context={"traffic_pct": 12})
    body = json.loads(req.model_dump_json())
    assert body["context"] == {"traffic_pct": 12}


# ---- manifest parsing -------------------------------------------------------

def test_manifest_parses_inferred_and_threshold_args():
    m = load_manifest({"enforce": [
        {"tool": "recall_*", "evidence": {
            "kind": "source", "source_type": "long_term_memory",
            "customer_id": "args.customer_id", "fields": {"dob": "result.dob"},
            "inferred": True}},
        {"tool": "run_experiment", "evidence": {
            "kind": "action", "action_type": "run_experiment",
            "threshold_args": ["traffic_pct"]}},
    ]})
    assert m.rules[0].evidence.inferred is True
    assert m.rules[1].evidence.threshold_args == ("traffic_pct",)


def test_manifest_inferred_defaults_false():
    m = load_manifest({"enforce": [
        {"tool": "get_*", "evidence": {"kind": "source", "source_type": "profile",
                                       "fields": {"dob": "result.dob"}}},
    ]})
    assert m.rules[0].evidence.inferred is False
    assert m.rules[0].evidence.threshold_args == ()


# ---- helpers ----------------------------------------------------------------

def test_fact_request_carries_inferred_flag():
    rule = EvidenceRule(kind="source", source_type="long_term_memory", inferred=True)
    req = _fact_request(rule, "sess_1", "c1", "agent", "date_of_birth", "1988-05-12")
    assert req.is_inferred is True


def test_threshold_context_narrows_to_declared_args():
    rule = EvidenceRule(kind="action", action_type="run_experiment", threshold_args=("traffic_pct",))
    ctx = _threshold_context(rule, {"traffic_pct": 12, "name": "promo", "secret": "x"})
    assert ctx == {"traffic_pct": 12}


def test_threshold_context_forwards_all_when_unset():
    rule = EvidenceRule(kind="action", action_type="run_experiment")
    ctx = _threshold_context(rule, {"traffic_pct": 12, "name": "promo"})
    assert ctx == {"traffic_pct": 12, "name": "promo"}


# ---- end-to-end over the wire ----------------------------------------------

@respx.mock
def test_observe_source_posts_is_inferred():
    client = bylaw.configure(_config("observe"))
    facts = respx.post("https://vault.test/v1/evidence/facts").mock(
        return_value=Response(201, json={"status": "registered", "fact": {"id": "fact_dob", "field": "date_of_birth"}})
    )

    from bylaw_python.evidence import observe_source

    rule = EvidenceRule(
        kind="source", source_type="long_term_memory", customer_id="args.customer_id",
        fields={"date_of_birth": "result.dob"}, inferred=True,
    )
    observe_source(client, rule, {"customer_id": "cust_42"}, {"dob": "1988-05-12"})

    body = json.loads(facts.calls.last.request.content)
    assert body["is_inferred"] is True
    assert body["source_type"] == "long_term_memory"


@respx.mock
def test_guard_action_posts_threshold_context():
    client = bylaw.configure(_config("observe"))
    check = respx.post("https://vault.test/v1/evidence/check-action").mock(
        return_value=Response(200, json={"decision": "review", "reason": "high traffic", "action_type": "run_experiment"})
    )

    from bylaw_python.evidence import guard_action

    rule = EvidenceRule(
        kind="action", action_type="run_experiment", customer_id="args.customer_id",
        threshold_args=("traffic_pct",),
    )
    guard_action(client, rule, {"customer_id": "cust_42", "traffic_pct": 12})

    body = json.loads(check.calls.last.request.content)
    assert body["context"] == {"traffic_pct": 12}
    assert body["action_type"] == "run_experiment"
