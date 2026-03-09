# Ledgix ALCV — Client Tests

from __future__ import annotations

import json

import httpx
import pytest
import respx
from httpx import Response

from ledgix_python import LedgixClient, VaultConfig
from ledgix_python.exceptions import (
    ClearanceDeniedError,
    PolicyRegistrationError,
    TokenVerificationError,
    VaultConnectionError,
)
from ledgix_python.models import ClearanceRequest, PolicyRegistration


# ──────────────────────────────────────────────────────────────────────
# Clearance — sync
# ──────────────────────────────────────────────────────────────────────


class TestRequestClearance:
    """Tests for LedgixClient.request_clearance (sync)."""

    @respx.mock
    def test_approved(self, client: LedgixClient, approved_response: dict):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        request = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45})
        result = client.request_clearance(request)

        assert result.approved is True
        assert result.token is not None
        assert result.request_id == "req-001"

    @respx.mock
    def test_denied_raises_error(self, client: LedgixClient, denied_response: dict):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=denied_response)
        )

        request = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 5000})

        with pytest.raises(ClearanceDeniedError) as exc_info:
            client.request_clearance(request)

        assert "exceeds $100" in exc_info.value.reason
        assert exc_info.value.request_id == "req-002"

    @respx.mock
    def test_connection_error(self, client: LedgixClient):
        respx.post("https://vault.test/request-clearance").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        request = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45})

        with pytest.raises(VaultConnectionError):
            client.request_clearance(request)

    @respx.mock
    def test_http_error(self, client: LedgixClient):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(500, text="Internal Server Error")
        )

        request = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45})

        with pytest.raises(VaultConnectionError, match="500"):
            client.request_clearance(request)

    @respx.mock
    def test_sends_correct_headers(self, client: LedgixClient, approved_response: dict):
        route = respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        request = ClearanceRequest(tool_name="test_tool", tool_args={})
        client.request_clearance(request)

        assert route.called
        sent_request = route.calls[0].request
        assert sent_request.headers["X-Vault-API-Key"] == "test-api-key"
        assert sent_request.headers["Content-Type"] == "application/json"

    @respx.mock
    def test_sends_correct_payload(self, client: LedgixClient, approved_response: dict):
        route = respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        request = ClearanceRequest(
            tool_name="stripe_refund",
            tool_args={"amount": 99, "reason": "late"},
            agent_id="my-agent",
            session_id="sess-123",
        )
        client.request_clearance(request)

        body = json.loads(route.calls[0].request.content)
        assert body["tool_name"] == "stripe_refund"
        assert body["tool_args"]["amount"] == 99
        assert body["agent_id"] == "my-agent"

    @respx.mock
    def test_processing_polls_until_approved(self, client: LedgixClient, approved_response: dict):
        processing_response = {
            "status": "processing",
            "approved": False,
            "token": None,
            "reason": "Queued",
            "request_id": "req-processing-001",
            "confidence": 0.0,
            "minimum_confidence_score": 0.8,
        }
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(202, json=processing_response)
        )
        respx.get("https://vault.test/clearance-status/req-processing-001").mock(
            return_value=Response(200, json={**approved_response, "request_id": "req-processing-001"})
        )

        request = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45})
        result = client.request_clearance(request)

        assert result.approved is True
        assert result.request_id == "req-processing-001"


# ──────────────────────────────────────────────────────────────────────
# Clearance — async
# ──────────────────────────────────────────────────────────────────────


class TestAsyncRequestClearance:
    """Tests for LedgixClient.arequest_clearance (async)."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_approved_async(self, client: LedgixClient, approved_response: dict):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        request = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45})
        result = await client.arequest_clearance(request)

        assert result.approved is True
        assert result.token is not None

    @respx.mock
    @pytest.mark.asyncio
    async def test_denied_async(self, client: LedgixClient, denied_response: dict):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=denied_response)
        )

        request = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 5000})

        with pytest.raises(ClearanceDeniedError):
            await client.arequest_clearance(request)

    @respx.mock
    @pytest.mark.asyncio
    async def test_connection_error_async(self, client: LedgixClient):
        respx.post("https://vault.test/request-clearance").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        request = ClearanceRequest(tool_name="stripe_refund", tool_args={})

        with pytest.raises(VaultConnectionError):
            await client.arequest_clearance(request)


# ──────────────────────────────────────────────────────────────────────
# Policy registration
# ──────────────────────────────────────────────────────────────────────


class TestPolicyRegistration:
    """Tests for policy registration (sync + async)."""

    @respx.mock
    def test_register_policy_sync(self, client: LedgixClient, policy_response: dict):
        respx.post("https://vault.test/register-policy").mock(
            return_value=Response(200, json=policy_response)
        )

        policy = PolicyRegistration(
            policy_id="refund-policy",
            description="Refund rules",
            rules=["Refunds up to $100"],
        )
        result = client.register_policy(policy)

        assert result.policy_id == "refund-policy"
        assert result.status == "registered"

    @respx.mock
    @pytest.mark.asyncio
    async def test_register_policy_async(self, client: LedgixClient, policy_response: dict):
        respx.post("https://vault.test/register-policy").mock(
            return_value=Response(200, json=policy_response)
        )

        policy = PolicyRegistration(
            policy_id="refund-policy",
            description="Refund rules",
            rules=["Refunds up to $100"],
        )
        result = await client.aregister_policy(policy)

        assert result.policy_id == "refund-policy"

    @respx.mock
    def test_register_policy_error(self, client: LedgixClient):
        respx.post("https://vault.test/register-policy").mock(
            return_value=Response(400, text="Bad Request")
        )

        policy = PolicyRegistration(policy_id="bad", rules=[])

        with pytest.raises(PolicyRegistrationError):
            client.register_policy(policy)


# ──────────────────────────────────────────────────────────────────────
# JWKS + Token verification
# ──────────────────────────────────────────────────────────────────────


class TestTokenVerification:
    """Tests for JWKS fetching and A-JWT verification."""

    @respx.mock
    def test_fetch_jwks(self, client: LedgixClient, jwks_response: dict):
        respx.get("https://vault.test/.well-known/jwks.json").mock(
            return_value=Response(200, json=jwks_response)
        )

        result = client.fetch_jwks()
        assert "keys" in result
        assert len(result["keys"]) == 1

    @respx.mock
    def test_verify_valid_token(
        self, client: LedgixClient, sample_jwt: str, jwks_response: dict
    ):
        respx.get("https://vault.test/.well-known/jwks.json").mock(
            return_value=Response(200, json=jwks_response)
        )

        decoded = client.verify_token(sample_jwt)
        assert decoded["sub"] == "clearance"
        assert decoded["tool"] == "stripe_refund"

    @respx.mock
    def test_verify_expired_token(
        self, client: LedgixClient, expired_jwt: str, jwks_response: dict
    ):
        respx.get("https://vault.test/.well-known/jwks.json").mock(
            return_value=Response(200, json=jwks_response)
        )

        with pytest.raises(TokenVerificationError, match="expired"):
            client.verify_token(expired_jwt)

    @respx.mock
    def test_verify_invalid_token(self, client: LedgixClient, jwks_response: dict):
        respx.get("https://vault.test/.well-known/jwks.json").mock(
            return_value=Response(200, json=jwks_response)
        )

        with pytest.raises(TokenVerificationError):
            client.verify_token("not.a.valid.token")

    @respx.mock
    def test_jwks_empty_keys(self, client: LedgixClient):
        respx.get("https://vault.test/.well-known/jwks.json").mock(
            return_value=Response(200, json={"keys": []})
        )

        with pytest.raises(TokenVerificationError, match="no keys"):
            client.verify_token("some.token.here")

    @respx.mock
    def test_clearance_with_jwt_verification(
        self, client_with_jwt: LedgixClient, approved_response: dict, jwks_response: dict
    ):
        """When verify_jwt=True, clearance should also verify the returned token."""
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )
        respx.get("https://vault.test/.well-known/jwks.json").mock(
            return_value=Response(200, json=jwks_response)
        )

        request = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45})
        result = client_with_jwt.request_clearance(request)

        assert result.approved is True


# ──────────────────────────────────────────────────────────────────────
# Client lifecycle
# ──────────────────────────────────────────────────────────────────────


class TestClientLifecycle:
    """Tests for context manager and close behavior."""

    def test_sync_context_manager(self, vault_config: VaultConfig):
        with LedgixClient(config=vault_config) as client:
            assert client.config.vault_url == "https://vault.test"

    @pytest.mark.asyncio
    async def test_async_context_manager(self, vault_config: VaultConfig):
        async with LedgixClient(config=vault_config) as client:
            assert client.config.vault_url == "https://vault.test"

    def test_default_config(self):
        """Client should work with defaults (reads env)."""
        client = LedgixClient()
        assert client.config.vault_url == "http://localhost:8000"
        client.close()
