# Ledgix ALCV — Model Tests
# Tests for Pydantic model serialization and validation

from __future__ import annotations

import pytest

from ledgix_python.models import (
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


class TestClearanceResponse:
    def test_approved(self):
        resp = ClearanceResponse(
            approved=True,
            token="eyJ...",
            reason="All good",
            request_id="req-1",
        )
        assert resp.approved is True
        assert resp.token == "eyJ..."

    def test_denied(self):
        resp = ClearanceResponse(
            approved=False,
            reason="Policy violation",
            request_id="req-2",
        )
        assert resp.approved is False
        assert resp.token is None

    def test_from_dict(self):
        data = {
            "approved": True,
            "token": "abc",
            "reason": "ok",
            "request_id": "r1",
        }
        resp = ClearanceResponse.model_validate(data)
        assert resp.approved is True


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
        with pytest.raises(Exception):
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
