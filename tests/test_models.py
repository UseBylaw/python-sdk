# Bylaw ALCV — Model Tests
# Tests for Pydantic model serialization and validation

from __future__ import annotations

import pytest
from pydantic import ValidationError

from bylaw_python.models import (
    ClearanceRequest,
    ClearanceResponse,
    PolicyRegistration,
    PolicyRegistrationResponse,
)


class TestClearanceRequest:
    def test_minimal(self):
        req = ClearanceRequest(tool_name="my_tool")
        assert req.tool_name == "my_tool"
        assert req.tool_args == {}
        assert req.agent_id == "default-agent"
        assert req.context == {}

    def test_full(self):
        req = ClearanceRequest(
            tool_name="stripe_refund",
            tool_args={"amount": 45, "reason": "late"},
            agent_id="agent-1",
            session_id="sess-1",
            context={"policy_id": "refund-policy"},
        )
        assert req.tool_args["amount"] == 45
        assert req.context["policy_id"] == "refund-policy"

    def test_serialization_roundtrip(self):
        req = ClearanceRequest(
            tool_name="test", tool_args={"key": "value"}
        )
        data = req.model_dump()
        restored = ClearanceRequest.model_validate(data)
        assert restored.tool_name == req.tool_name
        assert restored.tool_args == req.tool_args

    def test_json_roundtrip(self):
        req = ClearanceRequest(tool_name="test", tool_args={"x": 1})
        json_str = req.model_dump_json()
        restored = ClearanceRequest.model_validate_json(json_str)
        assert restored == req

    def test_phase_2_processing_register_fields(self):
        """Phase 2 (0.3.1): data_categories / purpose / processing_register_ref
        survive a JSON round-trip and default to None when omitted."""
        req = ClearanceRequest(
            tool_name="customer_export",
            data_categories=["customer_email", "transaction_amount"],
            purpose="billing",
            processing_register_ref="00000000-0000-0000-0000-000000000001",
        )
        assert req.data_categories == ["customer_email", "transaction_amount"]
        assert req.purpose == "billing"
        assert req.processing_register_ref == "00000000-0000-0000-0000-000000000001"

        restored = ClearanceRequest.model_validate_json(req.model_dump_json())
        assert restored.data_categories == req.data_categories
        assert restored.purpose == req.purpose
        assert restored.processing_register_ref == req.processing_register_ref

        # Defaults are None when omitted.
        bare = ClearanceRequest(tool_name="x")
        assert bare.data_categories is None
        assert bare.purpose is None
        assert bare.processing_register_ref is None

    def test_phase_6_dataset_ref_field(self):
        """Phase 6 (0.3.1): dataset_ref survives a JSON round-trip."""
        req = ClearanceRequest(
            tool_name="kb_search",
            dataset_ref="prod_customer_support_kb",
        )
        assert req.dataset_ref == "prod_customer_support_kb"

        restored = ClearanceRequest.model_validate_json(req.model_dump_json())
        assert restored.dataset_ref == req.dataset_ref

        bare = ClearanceRequest(tool_name="x")
        assert bare.dataset_ref is None


class TestClearanceResponse:
    def test_approved(self):
        resp = ClearanceResponse(
            decision_status="approved",
            token="eyJ...",
            reason="All good",
            request_id="req-1",
        )
        assert resp.is_approved is True
        assert resp.token == "eyJ..."

    def test_denied(self):
        resp = ClearanceResponse(
            decision_status="denied",
            reason="Policy violation",
            request_id="req-2",
        )
        assert resp.is_approved is False
        assert resp.token is None

    def test_from_dict(self):
        data = {
            "decision_status": "approved",
            "token": "abc",
            "reason": "ok",
            "request_id": "r1",
        }
        resp = ClearanceResponse.model_validate(data)
        assert resp.is_approved is True

    def test_policy_version_fields_default_none(self):
        resp = ClearanceResponse(decision_status="approved")
        assert resp.policy_version_id is None
        assert resp.policy_content_hash is None

    def test_policy_version_fields_round_trip(self):
        data = {
            "decision_status": "approved",
            "token": "tok",
            "request_id": "r1",
            "policy_version_id": "3b6b2e1d-9d7d-4a32-9f6e-54a4b0ee8e11",
            "policy_content_hash": "sha256:abcd1234",
        }
        resp = ClearanceResponse.model_validate(data)
        assert resp.policy_version_id == "3b6b2e1d-9d7d-4a32-9f6e-54a4b0ee8e11"
        assert resp.policy_content_hash == "sha256:abcd1234"
        restored = ClearanceResponse.model_validate_json(resp.model_dump_json())
        assert restored == resp


class TestPolicyRegistration:
    def test_minimal(self):
        policy = PolicyRegistration(policy_id="p1")
        assert policy.policy_id == "p1"
        assert policy.rules == []
        assert policy.tools == []

    def test_full(self):
        policy = PolicyRegistration(
            policy_id="refund-policy",
            description="Refund rules",
            rules=["Max $100", "Original customer only"],
            tools=["stripe_refund"],
        )
        assert len(policy.rules) == 2
        assert "stripe_refund" in policy.tools

    def test_missing_required_field(self):
        with pytest.raises(ValidationError):
            PolicyRegistration()  # policy_id is required


class TestPolicyRegistrationResponse:
    def test_defaults(self):
        resp = PolicyRegistrationResponse(policy_id="p1")
        assert resp.status == "registered"
        assert resp.message == ""

    def test_full(self):
        resp = PolicyRegistrationResponse(
            policy_id="p1",
            status="active",
            message="Ready",
        )
        assert resp.status == "active"
