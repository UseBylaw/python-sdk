"""Wire-contract cross-side tests.

These tests pin the SDK's request payloads against the *canonical* wire
fixtures committed in the Vault repo
(``vault/internal/api/testdata/wire/*.json``). The fixtures are copied
verbatim into ``tests/wire_fixtures/`` — they are the source of truth for
what the server accepts.

Direction of the contract: every top-level key the SDK *emits* must be a key
the server's fixture *accepts* (``sdk_keys ⊆ contract_keys``). The SDK must
never invent a field the server does not know about, because the server may
reject (or silently drop) unknown fields.

KNOWN_GAPS below records the small set of keys the SDK emits at top level that
the current Vault fixture does not list. Each one is a genuine divergence to
reconcile on the Vault side (the fixture should grow the field), NOT a license
for the SDK to drift further. The tests assert the gap set is *exactly* these
keys — so a newly invented SDK field, or a gap that gets fixed in the fixture,
fails this test and forces a deliberate update.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from bylaw_python.models import (
    CheckActionRequest,
    CheckOutputRequest,
    ClearanceRequest,
    FactRef,
    OutputClaim,
    RegisterFactRequest,
)

FIXTURE_DIR = Path(__file__).parent / "wire_fixtures"


def _load_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURE_DIR / name).read_text())


def _wire_dict(model: Any) -> dict[str, Any]:
    """Serialize the way the SDK actually sends a request body.

    ``BylawClient`` posts ``request.model_dump_json(...)``; we mirror that and
    drop nulls so we compare only the keys that go on the wire.
    """
    return json.loads(model.model_dump_json(exclude_none=True))


# Keys the SDK emits at top level that the canonical Vault fixture does not yet
# list. These are reconciliation TODOs on the Vault fixtures, documented in the
# test report. They are NOT silently ignored: the tests assert the gap set is
# exactly this, so any new drift fails.
#
#   request_clearance: SDK promotes ``purpose`` / ``data_categories`` to top
#     level (Phase 2 GDPR Article 30 matching). The fixture currently nests the
#     same information under ``context``.
#   check_action: SDK emits ``obligations`` (list of required obligation codes);
#     the fixture omits it.
KNOWN_GAPS: dict[str, set[str]] = {
    "request_clearance.json": {"purpose", "data_categories"},
    "register_fact.json": set(),
    "check_action.json": {"obligations"},
    "check_output.json": set(),
}


def _build_clearance() -> ClearanceRequest:
    # Mirror request_clearance.json's example values.
    return ClearanceRequest(
        tool_name="stripe_refund",
        tool_args={"amount": 45},
        agent_id="agent-checkout-bot",
        session_id="sess_9f3c1a2b",
        human_principal="auth0|user_5512",
        destination_uri="https://api.stripe.com/v1/refunds",
        destination_provider="stripe",
        destination_account_ref="acct_1QabcdEFGH",
        context={
            "policy_id": "refund_policy_v1",
            "action_category": "payment.refund",
            "action_metadata": {"currency": "usd", "charge_id": "ch_3Pxyz"},
        },
        purpose="customer_service_refund",
        data_categories=["financial"],
    )


def _build_register_fact() -> RegisterFactRequest:
    # Mirror register_fact.json's example values.
    return RegisterFactRequest(
        customer_id="cust_4421",
        session_id="sess_9f3c1a2b",
        field="risk_tolerance",
        value="moderate",
        source_type="document",
        source_id="doc_kyc_2026_03",
        source_actor="advisor@acme.example",
        scope="profile",
        authority_level="verified",
        is_inferred=False,
        metadata={"page": 2},
    )


def _build_check_action() -> CheckActionRequest:
    # Mirror check_action.json's example values.
    return CheckActionRequest(
        customer_id="cust_4421",
        session_id="sess_9f3c1a2b",
        mode="enforce",
        action_type="update_profile",
        workflow="advisory_chat",
        facts=[FactRef(fact_id="fact_abc123")],
        obligations=[],
        current_turn=3,
        context={"channel": "web"},
    )


def _build_check_output() -> CheckOutputRequest:
    # Mirror check_output.json's example values.
    return CheckOutputRequest(
        customer_id="cust_4421",
        session_id="sess_9f3c1a2b",
        mode="enforce",
        action_type="generate_recommendation",
        workflow="advisory_chat",
        response_text=(
            "Based on your moderate risk tolerance, consider a balanced "
            "60/40 portfolio."
        ),
        facts=[FactRef(fact_id="fact_abc123")],
        output_claims=[
            OutputClaim(
                claim_text="Your risk tolerance is moderate.",
                claim_type="fact_reference",
                value="moderate",
                source_fact_id="fact_abc123",
                source_type="document",
                source_field="risk_tolerance",
            )
        ],
        current_turn=4,
    )


CASES = [
    ("request_clearance.json", _build_clearance),
    ("register_fact.json", _build_register_fact),
    ("check_action.json", _build_check_action),
    ("check_output.json", _build_check_output),
]


@pytest.mark.parametrize("fixture_name,builder", CASES)
def test_sdk_keys_are_subset_of_contract(fixture_name, builder):
    """sdk_keys - known_gaps ⊆ contract_keys, and the gap set is exactly KNOWN_GAPS."""
    contract = _load_fixture(fixture_name)
    wire = _wire_dict(builder())

    contract_keys = set(contract.keys())
    sdk_keys = set(wire.keys())

    actual_gap = sdk_keys - contract_keys
    expected_gap = KNOWN_GAPS[fixture_name]

    # Surface any *unexpected* invented field loudly.
    unexpected = actual_gap - expected_gap
    assert not unexpected, (
        f"{fixture_name}: SDK emits top-level key(s) not in the Vault fixture "
        f"and not in KNOWN_GAPS: {sorted(unexpected)}. Either add the field to "
        f"the Vault wire fixture or stop emitting it."
    )
    # If a known gap is silently fixed in the fixture, force a KNOWN_GAPS update.
    resolved = expected_gap - actual_gap
    assert not resolved, (
        f"{fixture_name}: KNOWN_GAPS lists {sorted(resolved)} but the fixture "
        f"now accepts them — remove from KNOWN_GAPS."
    )

    # The real contract guarantee: everything except the documented gaps is
    # accepted by the server.
    assert sdk_keys - expected_gap <= contract_keys


def test_clearance_required_fields_emitted():
    wire = _wire_dict(_build_clearance())
    assert "tool_name" in wire
    assert wire["tool_name"] == "stripe_refund"


def test_register_fact_required_fields_emitted():
    wire = _wire_dict(_build_register_fact())
    for key in ("field", "source_type", "value"):
        assert key in wire, f"register_fact must emit {key!r}"
    assert wire["field"] == "risk_tolerance"
    assert wire["source_type"] == "document"
    assert wire["value"] == "moderate"


def test_check_action_required_fields_emitted():
    wire = _wire_dict(_build_check_action())
    assert "action_type" in wire
    assert wire["action_type"] == "update_profile"


def test_check_output_present_fields_emitted():
    wire = _wire_dict(_build_check_output())
    # check_output is structurally present (response_text + claims grounding).
    assert "response_text" in wire
    assert "output_claims" in wire


def test_clearance_nested_context_keys_match_fixture():
    """Spot-check that nested context object names line up with the fixture."""
    contract = _load_fixture("request_clearance.json")
    wire = _wire_dict(_build_clearance())
    contract_ctx_keys = set(contract["context"].keys())
    wire_ctx_keys = set(wire["context"].keys())
    # The context names the SDK sends must be ones the fixture demonstrates.
    overlap = wire_ctx_keys & contract_ctx_keys
    assert {"policy_id", "action_category", "action_metadata"} <= overlap


def test_facts_nested_keys_match_fixture():
    """facts[] nested key name (fact_id) matches across both check requests."""
    for fixture_name, builder in (
        ("check_action.json", _build_check_action),
        ("check_output.json", _build_check_output),
    ):
        contract = _load_fixture(fixture_name)
        wire = _wire_dict(builder())
        contract_fact_keys = set(contract["facts"][0].keys())
        wire_fact_keys = set(wire["facts"][0].keys())
        assert wire_fact_keys == {"fact_id"}
        assert wire_fact_keys <= contract_fact_keys


def test_output_claims_nested_keys_match_fixture():
    """output_claims[] nested key names are a subset of the fixture's example."""
    contract = _load_fixture("check_output.json")
    wire = _wire_dict(_build_check_output())
    contract_claim_keys = set(contract["output_claims"][0].keys())
    wire_claim_keys = set(wire["output_claims"][0].keys())
    assert wire_claim_keys <= contract_claim_keys, (
        f"output_claims emits keys not in fixture: "
        f"{sorted(wire_claim_keys - contract_claim_keys)}"
    )
    # Spot-check the load-bearing provenance names are present on both sides.
    assert {"claim_text", "source_fact_id", "source_type"} <= wire_claim_keys
