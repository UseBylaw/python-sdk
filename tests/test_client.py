# Bylaw ALCV — Client Tests

from __future__ import annotations

import base64
import hashlib
import json
import struct

import httpx
import pytest
import respx
from httpx import Response

from bylaw_python import BylawClient, VaultConfig
from bylaw_python.exceptions import (
    ClearanceDeniedError,
    PolicyRegistrationError,
    ReviewPendingError,
    TokenVerificationError,
    VaultConnectionError,
)
from bylaw_python.models import ClearanceRequest, PolicyRegistration
from bylaw_python.otel import _set_otel_api_for_tests


class _FakeSpanContext:
    trace_id = int("0af7651916cd43dd8448eb211c80319c", 16)
    span_id = int("b7ad6b7169203331", 16)
    trace_flags = 1
    trace_state = "vendor=value"
    is_valid = True


class _FakeSpan:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def get_span_context(self) -> _FakeSpanContext:
        return _FakeSpanContext()

    def add_event(self, name: str, attrs: dict) -> None:
        self.events.append((name, attrs))


class _FakeTrace:
    def __init__(self, span: _FakeSpan) -> None:
        self.span = span

    def get_current_span(self) -> _FakeSpan:
        return self.span


class _FakePropagate:
    def inject(self, carrier: dict[str, str]) -> None:
        carrier["traceparent"] = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"


@pytest.fixture(autouse=True)
def _reset_otel_test_api():
    _set_otel_api_for_tests(None)
    yield
    _set_otel_api_for_tests()


# ──────────────────────────────────────────────────────────────────────
# Clearance — sync
# ──────────────────────────────────────────────────────────────────────


class TestRequestClearance:
    """Tests for BylawClient.request_clearance (sync)."""

    @respx.mock
    def test_approved(self, client: BylawClient, approved_response: dict):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        request = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45})
        result = client.request_clearance(request)

        assert result.is_approved is True
        assert result.token is not None
        assert result.request_id == "req-001"

    @respx.mock
    def test_denied_raises_error(self, client: BylawClient, denied_response: dict):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=denied_response)
        )

        request = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 5000})

        with pytest.raises(ClearanceDeniedError) as exc_info:
            client.request_clearance(request)

        assert "exceeds $100" in exc_info.value.reason
        assert exc_info.value.request_id == "req-002"

    @respx.mock
    def test_connection_error(self, client: BylawClient):
        respx.post("https://vault.test/request-clearance").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        request = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45})

        with pytest.raises(VaultConnectionError):
            client.request_clearance(request)

    @respx.mock
    def test_http_error(self, client: BylawClient):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(500, text="Internal Server Error")
        )

        request = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45})

        with pytest.raises(VaultConnectionError, match="500"):
            client.request_clearance(request)

    @respx.mock
    def test_sends_correct_headers(self, client: BylawClient, approved_response: dict):
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
    def test_sends_correct_payload(self, client: BylawClient, approved_response: dict):
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
    def test_otel_active_span_adds_context_headers_and_decision_event(self, client: BylawClient, approved_response: dict):
        span = _FakeSpan()
        _set_otel_api_for_tests((_FakeTrace(span), _FakePropagate()))
        approved_response.update(
            {
                "reason_code": "ok",
                "policy_version_id": "pv-1",
                "policy_content_hash": "sha256:abc",
                "confidence_bucket": "extra_high",
                "minimum_confidence_bucket": "medium",
                "latency_ms": 12,
            }
        )
        route = respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        client.request_clearance(
            ClearanceRequest(
                tool_name="stripe_refund",
                tool_args={"amount": 99},
                agent_id="my-agent",
                session_id="sess-123",
                context={"policy_id": "refunds"},
            )
        )

        sent = route.calls[0].request
        assert (
            sent.headers["traceparent"]
            == "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        )
        body = json.loads(sent.content)
        assert body["context"]["telemetry"]["otel"] == {
            "trace_id": "0af7651916cd43dd8448eb211c80319c",
            "span_id": "b7ad6b7169203331",
            "trace_flags": 1,
            "trace_state": "vendor=value",
        }
        assert span.events[0][0] == "ledgix.clearance.decision"
        assert span.events[0][1]["ledgix.request_id"] == "req-001"
        assert span.events[0][1]["ledgix.decision_status"] == "approved"
        assert span.events[0][1]["ledgix.latency_ms"] == 12

    @respx.mock
    def test_otel_active_span_adds_context_headers_to_cache_hit_mint_token(
        self, vault_config: VaultConfig, approved_response: dict, sample_jwt: str
    ):
        span = _FakeSpan()
        _set_otel_api_for_tests((_FakeTrace(span), _FakePropagate()))
        client = BylawClient(vault_config.model_copy(update={"decision_cache_enabled": True}))
        approved_response.update(
            {
                "policy_version_id": "pv-1",
                "policy_content_hash": "sha256:abc",
                "confidence_bucket": "extra_high",
                "minimum_confidence_bucket": "medium",
            }
        )
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )
        mint_route = respx.post("https://vault.test/mint-token").mock(
            return_value=Response(
                200,
                json={
                    "request_id": "req-mint-001",
                    "token": sample_jwt,
                    "decision_status": "approved",
                    "reason": "Policy passed",
                },
            )
        )

        request = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45})
        client.request_clearance(request)
        client.request_clearance(request)

        sent = mint_route.calls[0].request
        assert (
            sent.headers["traceparent"]
            == "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        )
        assert "Idempotency-Key" in sent.headers
        client.close()

    @respx.mock
    def test_otel_absent_is_noop(self, client: BylawClient, approved_response: dict):
        _set_otel_api_for_tests(None)
        route = respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        result = client.request_clearance(ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45}))

        body = json.loads(route.calls[0].request.content)
        assert "telemetry" not in body.get("context", {})
        assert result.is_approved is True

    @respx.mock
    def test_otel_denial_event_before_error(self, client: BylawClient, denied_response: dict):
        span = _FakeSpan()
        _set_otel_api_for_tests((_FakeTrace(span), _FakePropagate()))
        denied_response["reason_code"] = "spend_cap_exceeded"
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=denied_response)
        )

        with pytest.raises(ClearanceDeniedError):
            client.request_clearance(ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 5000}))

        assert span.events[0][0] == "ledgix.clearance.decision"
        assert span.events[0][1]["ledgix.decision_status"] == "denied"
        assert span.events[0][1]["ledgix.reason_code"] == "spend_cap_exceeded"

    @respx.mock
    def test_otel_pending_review_event_before_detach_error(self, vault_config: VaultConfig):
        span = _FakeSpan()
        _set_otel_api_for_tests((_FakeTrace(span), _FakePropagate()))
        client = BylawClient(vault_config.model_copy(update={"review_mode": "detach"}))
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(
                200,
                json={
                    "status": "pending_review",
                    "decision_status": "approved_pending_review",
                    "requires_manual_review": True,
                    "token": None,
                    "reason": "Needs review",
                    "request_id": "req-review-001",
                    "confidence_bucket": "low",
                    "minimum_confidence_bucket": "medium",
                },
            )
        )

        with pytest.raises(ReviewPendingError):
            client.request_clearance(ClearanceRequest(tool_name="wire_transfer", tool_args={"amount": 5000}))

        assert span.events[0][0] == "ledgix.clearance.pending_review"
        assert span.events[0][1]["ledgix.request_id"] == "req-review-001"
        assert span.events[0][1]["ledgix.requires_manual_review"] is True

    @respx.mock
    def test_processing_polls_until_approved(self, client: BylawClient, approved_response: dict):
        processing_response = {
            "status": "processing",
            "decision_status": "denied",
            "token": None,
            "reason": "Queued",
            "request_id": "req-processing-001",
            "confidence_bucket": "none",
            "minimum_confidence_bucket": "medium",
        }
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(202, json=processing_response)
        )
        respx.get("https://vault.test/clearance-status/req-processing-001").mock(
            return_value=Response(200, json={**approved_response, "request_id": "req-processing-001"})
        )

        request = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45})
        result = client.request_clearance(request)

        assert result.is_approved is True
        assert result.request_id == "req-processing-001"

    @respx.mock
    def test_otel_active_span_adds_context_headers_to_processing_poll(
        self, vault_config: VaultConfig, approved_response: dict
    ):
        span = _FakeSpan()
        _set_otel_api_for_tests((_FakeTrace(span), _FakePropagate()))
        client = BylawClient(vault_config.model_copy(update={"review_poll_interval": 0.0}))
        processing_response = {
            "status": "processing",
            "decision_status": "denied",
            "token": None,
            "reason": "Queued",
            "request_id": "req-processing-001",
            "confidence_bucket": "none",
            "minimum_confidence_bucket": "medium",
        }
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(202, json=processing_response)
        )
        poll_route = respx.get("https://vault.test/clearance-status/req-processing-001").mock(
            return_value=Response(200, json={**approved_response, "request_id": "req-processing-001"})
        )

        result = client.request_clearance(ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45}))

        sent = poll_route.calls[0].request
        assert (
            sent.headers["traceparent"]
            == "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        )
        assert result.is_approved is True
        client.close()


# ──────────────────────────────────────────────────────────────────────
# Clearance — async
# ──────────────────────────────────────────────────────────────────────


class TestAsyncRequestClearance:
    """Tests for BylawClient.arequest_clearance (async)."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_approved_async(self, client: BylawClient, approved_response: dict):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        request = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45})
        result = await client.arequest_clearance(request)

        assert result.is_approved is True
        assert result.token is not None

    @respx.mock
    @pytest.mark.asyncio
    async def test_otel_active_span_adds_context_headers_and_decision_event_async(
        self, client: BylawClient, approved_response: dict
    ):
        span = _FakeSpan()
        _set_otel_api_for_tests((_FakeTrace(span), _FakePropagate()))
        route = respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        result = await client.arequest_clearance(
            ClearanceRequest(
                tool_name="stripe_refund",
                tool_args={"amount": 99},
                agent_id="my-agent",
                session_id="sess-123",
                context={"policy_id": "refunds"},
            )
        )

        sent = route.calls[0].request
        assert (
            sent.headers["traceparent"]
            == "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        )
        body = json.loads(sent.content)
        assert body["context"]["telemetry"]["otel"]["trace_id"] == "0af7651916cd43dd8448eb211c80319c"
        assert body["context"]["telemetry"]["otel"]["span_id"] == "b7ad6b7169203331"
        assert span.events[0][0] == "ledgix.clearance.decision"
        assert span.events[0][1]["ledgix.request_id"] == "req-001"
        assert result.is_approved is True

    @respx.mock
    @pytest.mark.asyncio
    async def test_otel_active_span_adds_context_headers_to_cache_hit_mint_token_async(
        self, vault_config: VaultConfig, approved_response: dict, sample_jwt: str
    ):
        span = _FakeSpan()
        _set_otel_api_for_tests((_FakeTrace(span), _FakePropagate()))
        client = BylawClient(vault_config.model_copy(update={"decision_cache_enabled": True}))
        approved_response.update(
            {
                "policy_version_id": "pv-1",
                "policy_content_hash": "sha256:abc",
                "confidence_bucket": "extra_high",
                "minimum_confidence_bucket": "medium",
            }
        )
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )
        mint_route = respx.post("https://vault.test/mint-token").mock(
            return_value=Response(
                200,
                json={
                    "request_id": "req-mint-async-001",
                    "token": sample_jwt,
                    "decision_status": "approved",
                    "reason": "Policy passed",
                },
            )
        )

        request = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45})
        await client.arequest_clearance(request)
        await client.arequest_clearance(request)

        sent = mint_route.calls[0].request
        assert (
            sent.headers["traceparent"]
            == "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        )
        assert "Idempotency-Key" in sent.headers
        await client.aclose()

    @respx.mock
    @pytest.mark.asyncio
    async def test_otel_active_span_adds_context_headers_to_processing_poll_async(
        self, vault_config: VaultConfig, approved_response: dict
    ):
        span = _FakeSpan()
        _set_otel_api_for_tests((_FakeTrace(span), _FakePropagate()))
        client = BylawClient(vault_config.model_copy(update={"review_poll_interval": 0.0}))
        processing_response = {
            "status": "processing",
            "decision_status": "denied",
            "token": None,
            "reason": "Queued",
            "request_id": "req-processing-async-001",
            "confidence_bucket": "none",
            "minimum_confidence_bucket": "medium",
        }
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(202, json=processing_response)
        )
        poll_route = respx.get("https://vault.test/clearance-status/req-processing-async-001").mock(
            return_value=Response(
                200,
                json={**approved_response, "request_id": "req-processing-async-001"},
            )
        )

        result = await client.arequest_clearance(
            ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45})
        )

        sent = poll_route.calls[0].request
        assert (
            sent.headers["traceparent"]
            == "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        )
        assert result.is_approved is True
        await client.aclose()

    @respx.mock
    @pytest.mark.asyncio
    async def test_denied_async(self, client: BylawClient, denied_response: dict):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=denied_response)
        )

        request = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 5000})

        with pytest.raises(ClearanceDeniedError):
            await client.arequest_clearance(request)

    @respx.mock
    @pytest.mark.asyncio
    async def test_connection_error_async(self, client: BylawClient):
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
    def test_register_policy_sync(self, client: BylawClient, policy_response: dict):
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
    async def test_register_policy_async(self, client: BylawClient, policy_response: dict):
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
    def test_register_policy_error(self, client: BylawClient):
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
    def test_fetch_jwks(self, client: BylawClient, jwks_response: dict):
        respx.get("https://vault.test/.well-known/jwks.json").mock(
            return_value=Response(200, json=jwks_response)
        )

        result = client.fetch_jwks()
        assert "keys" in result
        assert len(result["keys"]) == 1

    @respx.mock
    def test_verify_valid_token(
        self, client: BylawClient, sample_jwt: str, jwks_response: dict
    ):
        respx.get("https://vault.test/.well-known/jwks.json").mock(
            return_value=Response(200, json=jwks_response)
        )

        decoded = client.verify_token(sample_jwt)
        assert decoded["sub"] == "clearance"
        assert decoded["tool"] == "stripe_refund"

    @respx.mock
    def test_verify_expired_token(
        self, client: BylawClient, expired_jwt: str, jwks_response: dict
    ):
        respx.get("https://vault.test/.well-known/jwks.json").mock(
            return_value=Response(200, json=jwks_response)
        )

        with pytest.raises(TokenVerificationError, match="expired"):
            client.verify_token(expired_jwt)

    @respx.mock
    def test_verify_invalid_token(self, client: BylawClient, jwks_response: dict):
        respx.get("https://vault.test/.well-known/jwks.json").mock(
            return_value=Response(200, json=jwks_response)
        )

        with pytest.raises(TokenVerificationError):
            client.verify_token("not.a.valid.token")

    @respx.mock
    def test_jwks_empty_keys(self, client: BylawClient):
        respx.get("https://vault.test/.well-known/jwks.json").mock(
            return_value=Response(200, json={"keys": []})
        )

        with pytest.raises(TokenVerificationError, match="no keys"):
            client.verify_token("some.token.here")

    @respx.mock
    def test_clearance_with_jwt_verification(
        self, client_with_jwt: BylawClient, approved_response: dict, jwks_response: dict
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

        assert result.is_approved is True


class TestLedgerProofVerification:
    """Tests for ledger fetch + offline proof verification."""

    @staticmethod
    def _b64url(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    @staticmethod
    def _cbor_header(major: int, value: int) -> bytes:
        if value <= 23:
            return bytes([(major << 5) | value])
        if value <= 0xFF:
            return bytes([(major << 5) | 24, value])
        if value <= 0xFFFF:
            return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
        if value <= 0xFFFFFFFF:
            return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
        return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")

    @classmethod
    def _encode_cbor(cls, value):
        if value is None:
            return b"\xf6"
        if isinstance(value, bool):
            return b"\xf5" if value else b"\xf4"
        if isinstance(value, str):
            encoded = value.encode("utf-8")
            return cls._cbor_header(3, len(encoded)) + encoded
        if isinstance(value, int):
            if value >= 0:
                return cls._cbor_header(0, value)
            return cls._cbor_header(1, -(value + 1))
        if isinstance(value, float):
            return b"\xfb" + struct.pack(">d", value)
        if isinstance(value, list):
            return cls._cbor_header(4, len(value)) + b"".join(cls._encode_cbor(item) for item in value)
        if isinstance(value, dict):
            keys = sorted(value.keys(), key=lambda item: (len(item), item))
            encoded = bytearray()
            for key in keys:
                encoded.extend(cls._encode_cbor(key))
                encoded.extend(cls._encode_cbor(value[key]))
            return cls._cbor_header(5, len(keys)) + bytes(encoded)
        raise TypeError(f"unsupported test CBOR value {type(value)!r}")

    @staticmethod
    def _sha256_hex(*parts: bytes) -> str:
        digest = hashlib.sha256()
        for part in parts:
            digest.update(part)
        return digest.hexdigest()

    @classmethod
    def _normalize_json_numbers(cls, value):
        if value is None or isinstance(value, (str, bool, float)):
            return value
        if isinstance(value, int):
            return float(value)
        if isinstance(value, list):
            return [cls._normalize_json_numbers(item) for item in value]
        if isinstance(value, dict):
            return {key: cls._normalize_json_numbers(item) for key, item in value.items()}
        return value

    @classmethod
    def _build_event_hash(cls, entry: dict) -> str:
        payload = cls._encode_cbor(
            {
                "accepted_at": entry["accepted_at"],
                "agent_id": entry["agent_id"],
                "approved": entry["approved"],
                "canonical_version": entry["canonical_version"],
                "citations": cls._normalize_json_numbers(entry["citations"]),
                "confidence": entry["confidence"],
                "event_uuid": entry["event_uuid"],
                "evidence_chunks": cls._normalize_json_numbers(entry["evidence_chunks"]),
                "intent_hash": entry["intent_hash"],
                "policy_id": entry["policy_id"],
                "reason": entry["reason"],
                "request_id": entry["request_id"],
                "tool_args": cls._normalize_json_numbers(entry["tool_args"]),
                "tool_name": entry["tool_name"],
            }
        )
        return cls._sha256_hex(b"ledgix.audit.event.v1\x00", payload)

    @classmethod
    def _hash_leaf(cls, event_hash: str) -> str:
        return cls._sha256_hex(b"\x00", bytes.fromhex(event_hash))

    @classmethod
    def _build_receipt_payload(cls, entry: dict) -> bytes:
        return cls._encode_cbor(
            {
                "accepted_at": entry["accepted_at"],
                "event_hash": entry["event_hash"],
                "event_uuid": entry["event_uuid"],
                "leaf_hash": entry["leaf_hash"],
                "receipt_key_id": entry["receipt_key_id"],
                "request_id": entry["request_id"],
                "type": "event_receipt",
                "version": 1,
            }
        )

    @classmethod
    def _build_checkpoint_payload(cls, checkpoint: dict) -> bytes:
        return cls._encode_cbor(
            {
                "export_targets": [checkpoint["export_target"]] if checkpoint["export_target"] else [],
                "key_id": checkpoint["signer_key_id"],
                "mmd_seconds": checkpoint["mmd_seconds"],
                "prev_checkpoint_hash": checkpoint["prev_checkpoint_hash"],
                "root_hash": checkpoint["root_hash"],
                "signed_at": checkpoint["signed_at"],
                "tree_size": checkpoint["tree_size"],
                "type": "checkpoint",
                "version": 1,
            }
        )

    @classmethod
    def _hash_checkpoint_payload(cls, payload: bytes) -> str:
        return cls._sha256_hex(b"ledgix.audit.checkpoint.v1\x00", payload)

    @respx.mock
    def test_fetch_ledger_and_manifests(self, client: BylawClient):
        respx.get("https://vault.test/ledger?limit=2").mock(
            return_value=Response(
                200,
                json={
                    "entries": [
                        {
                            "seq": 2,
                            "event_uuid": "evt-2",
                            "request_id": "req-2",
                            "agent_id": "agent-2",
                            "policy_id": "policy-2",
                            "intent_hash": "intent-2",
                            "tool_name": "stripe_refund",
                            "tool_args": {"amount": 60},
                            "reason": "approved",
                            "citations": [],
                            "evidence_chunks": [],
                            "confidence_bucket": "high",
            "decision_status": "approved",
            "confidence": 0.85,
            "approved": True,
                            "accepted_at": "2026-03-15T12:00:00Z",
                            "canonical_version": 1,
                            "event_hash": "a" * 64,
                            "leaf_hash": "b" * 64,
                            "leaf_index": 1,
                            "checkpoint_id": 7,
                            "receipt_algorithm": "Ed25519",
                            "receipt_key_id": "test-key-001",
                            "receipt_signature": "sig",
                            "receipt_payload": "payload",
                        }
                    ]
                },
            )
        )
        respx.get("https://vault.test/ledger/checkpoints?limit=3").mock(
            return_value=Response(
                200,
                json={
                    "checkpoints": [
                        {
                            "checkpoint_id": 7,
                            "microblock_id": 3,
                            "tree_size": 2,
                            "root_hash": "c" * 64,
                            "checkpoint_hash": "d" * 64,
                            "prev_checkpoint_hash": "",
                            "signature_algorithm": "Ed25519",
                            "signer_key_id": "test-key-001",
                            "checkpoint_signature": "sig",
                            "checkpoint_payload": "payload",
                            "signed_at": "2026-03-15T13:00:00Z",
                            "mmd_seconds": 30,
                        }
                    ]
                },
            )
        )

        entries = client.fetch_ledger(limit=2)
        manifests = client.fetch_ledger_manifests(limit=3)

        assert len(entries) == 1
        assert entries[0].request_id == "req-2"
        assert len(manifests) == 1
        assert manifests[0].tree_size == 2

    @respx.mock
    def test_verify_ledger_proof(
        self,
        client: BylawClient,
        ed25519_private_key,
        jwks_response: dict,
    ):
        entry = {
            "seq": 1,
            "event_uuid": "evt-1",
            "request_id": "req-1",
            "agent_id": "agent-1",
            "policy_id": "policy-1",
            "intent_hash": "intent-1",
            "tool_name": "stripe_refund",
            "tool_args": {"amount": 45},
            "reason": "ok",
            "citations": [],
            "evidence_chunks": [],
            "confidence_bucket": "high",
            "decision_status": "approved",
            "confidence": 0.85,
            "approved": True,
            "accepted_at": "2026-03-15T12:00:00Z",
            "canonical_version": 1,
            "event_hash": "",
            "leaf_hash": "",
            "leaf_index": 0,
            "checkpoint_id": 1,
            "receipt_algorithm": "Ed25519",
            "receipt_key_id": "test-key-001",
            "receipt_signature": "",
            "receipt_payload": "",
        }
        entry["event_hash"] = self._build_event_hash(entry)
        entry["leaf_hash"] = self._hash_leaf(entry["event_hash"])
        receipt_payload = self._build_receipt_payload(entry)
        entry["receipt_payload"] = self._b64url(receipt_payload)
        entry["receipt_signature"] = self._b64url(ed25519_private_key.sign(receipt_payload))

        checkpoint = {
            "checkpoint_id": 1,
            "microblock_id": 1,
            "tree_size": 1,
            "root_hash": entry["leaf_hash"],
            "checkpoint_hash": "",
            "prev_checkpoint_hash": "",
            "signature_algorithm": "Ed25519",
            "signer_key_id": "test-key-001",
            "checkpoint_signature": "",
            "checkpoint_payload": "",
            "signed_at": "2026-03-15T13:00:00Z",
            "mmd_seconds": 30,
            "export_target": "",
            "export_uri": "",
            "export_status": "",
        }
        checkpoint_payload = self._build_checkpoint_payload(checkpoint)
        checkpoint["checkpoint_hash"] = self._hash_checkpoint_payload(checkpoint_payload)
        checkpoint["checkpoint_payload"] = self._b64url(checkpoint_payload)
        checkpoint["checkpoint_signature"] = self._b64url(ed25519_private_key.sign(checkpoint_payload))

        respx.get("https://vault.test/.well-known/jwks.json").mock(
            return_value=Response(200, json=jwks_response)
        )

        result = client.verify_ledger_proof(
            entries=[entry],
            manifests=[checkpoint],
        )

        assert result.intact is True
        assert result.verified_entries == 1
        assert result.verified_manifests == 1
        assert result.latest_leaf_hash == entry["leaf_hash"]

    @respx.mock
    def test_verify_ledger_proof_with_redacted_public_entry(
        self,
        client: BylawClient,
        ed25519_private_key,
        jwks_response: dict,
    ):
        full_entry = {
            "seq": 1,
            "event_uuid": "evt-1",
            "request_id": "req-1",
            "agent_id": "agent-1",
            "policy_id": "policy-1",
            "intent_hash": "intent-1",
            "tool_name": "stripe_refund",
            "tool_args": {"amount": 45},
            "reason": "ok",
            "citations": [],
            "evidence_chunks": [],
            "confidence_bucket": "high",
            "decision_status": "approved",
            "confidence": 0.85,
            "approved": True,
            "accepted_at": "2026-03-15T12:00:00Z",
            "canonical_version": 1,
            "event_hash": "",
            "leaf_hash": "",
            "leaf_index": 0,
            "checkpoint_id": 1,
            "receipt_algorithm": "Ed25519",
            "receipt_key_id": "test-key-001",
            "receipt_signature": "",
            "receipt_payload": "",
        }
        full_entry["event_hash"] = self._build_event_hash(full_entry)
        full_entry["leaf_hash"] = self._hash_leaf(full_entry["event_hash"])
        receipt_payload = self._build_receipt_payload(full_entry)
        full_entry["receipt_payload"] = self._b64url(receipt_payload)
        full_entry["receipt_signature"] = self._b64url(ed25519_private_key.sign(receipt_payload))

        public_entry = {
            **full_entry,
            "intent_hash": "",
            "tool_args": {},
        }

        checkpoint = {
            "checkpoint_id": 1,
            "microblock_id": 1,
            "tree_size": 1,
            "root_hash": full_entry["leaf_hash"],
            "checkpoint_hash": "",
            "prev_checkpoint_hash": "",
            "signature_algorithm": "Ed25519",
            "signer_key_id": "test-key-001",
            "checkpoint_signature": "",
            "checkpoint_payload": "",
            "signed_at": "2026-03-15T13:00:00Z",
            "mmd_seconds": 30,
            "export_target": "",
            "export_uri": "",
            "export_status": "",
        }
        checkpoint_payload = self._build_checkpoint_payload(checkpoint)
        checkpoint["checkpoint_hash"] = self._hash_checkpoint_payload(checkpoint_payload)
        checkpoint["checkpoint_payload"] = self._b64url(checkpoint_payload)
        checkpoint["checkpoint_signature"] = self._b64url(ed25519_private_key.sign(checkpoint_payload))

        respx.get("https://vault.test/.well-known/jwks.json").mock(
            return_value=Response(200, json=jwks_response)
        )

        result = client.verify_ledger_proof(
            entries=[public_entry],
            manifests=[checkpoint],
        )

        assert result.intact is True
        assert result.verified_entries == 1
        assert result.coverage_note is not None
        assert "redacted public ledger entry" in result.coverage_note

    def test_verify_ledger_proof_bundle_with_later_checkpoint(
        self,
        client: BylawClient,
        ed25519_private_key,
        jwks_response: dict,
    ):
        event = {
            "seq": 21,
            "event_uuid": "evt-21",
            "request_id": "req-21",
            "agent_id": "agent-21",
            "policy_id": "policy-21",
            "intent_hash": "intent-21",
            "tool_name": "stripe_refund",
            "tool_args": {"amount": 45},
            "reason": "ok",
            "citations": [],
            "evidence_chunks": [],
            "confidence_bucket": "high",
            "decision_status": "approved",
            "confidence": 0.85,
            "approved": True,
            "accepted_at": "2026-03-15T12:00:00Z",
            "canonical_version": 1,
            "event_hash": "",
            "leaf_hash": "",
            "leaf_index": 0,
            "checkpoint_id": 21,
            "receipt_algorithm": "Ed25519",
            "receipt_key_id": "test-key-001",
            "receipt_signature": "",
            "receipt_payload": "",
        }
        event["event_hash"] = self._build_event_hash(event)
        event["leaf_hash"] = self._hash_leaf(event["event_hash"])
        receipt_payload = self._build_receipt_payload(event)
        event["receipt_payload"] = self._b64url(receipt_payload)
        event["receipt_signature"] = self._b64url(ed25519_private_key.sign(receipt_payload))

        checkpoint = {
            "checkpoint_id": 21,
            "microblock_id": 21,
            "tree_size": 1,
            "root_hash": event["leaf_hash"],
            "checkpoint_hash": "",
            "prev_checkpoint_hash": "prev-checkpoint-hash-20",
            "signature_algorithm": "Ed25519",
            "signer_key_id": "test-key-001",
            "checkpoint_signature": "",
            "checkpoint_payload": "",
            "signed_at": "2026-03-15T13:00:00Z",
            "mmd_seconds": 30,
            "export_target": "",
            "export_uri": "",
            "export_status": "",
        }
        checkpoint_payload = self._build_checkpoint_payload(checkpoint)
        checkpoint["checkpoint_hash"] = self._hash_checkpoint_payload(checkpoint_payload)
        checkpoint["checkpoint_payload"] = self._b64url(checkpoint_payload)
        checkpoint["checkpoint_signature"] = self._b64url(ed25519_private_key.sign(checkpoint_payload))

        public_jwk = self._b64url(json.dumps(jwks_response["keys"][0]).encode("utf-8"))
        bundle = {
            "event": event,
            "inclusion": {
                "event_uuid": event["event_uuid"],
                "request_id": event["request_id"],
                "event_hash": event["event_hash"],
                "leaf_hash": event["leaf_hash"],
                "leaf_index": 0,
                "tree_size": 1,
                "path": [],
                "checkpoint": checkpoint,
            },
            "keys": [
                {
                    "key_id": "test-key-001",
                    "algorithm": "Ed25519",
                    "public_jwk": public_jwk,
                    "active_from": "2026-03-15T11:00:00Z",
                    "attestation_status": "verified",
                }
            ],
        }

        result = client.verify_ledger_proof_bundle(bundle)

        assert result.intact is True
        assert result.verified_entries == 1
        assert result.verified_checkpoints == 1
        assert result.latest_checkpoint_hash == checkpoint["checkpoint_hash"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_verify_ledger_proof_async(
        self,
        client: BylawClient,
        ed25519_private_key,
        jwks_response: dict,
    ):
        entry = {
            "seq": 2,
            "event_uuid": "evt-2",
            "request_id": "req-2",
            "agent_id": "agent-2",
            "policy_id": "policy-2",
            "intent_hash": "intent-2",
            "tool_name": "stripe_refund",
            "tool_args": {"amount": 60},
            "reason": "ok",
            "citations": [],
            "evidence_chunks": [],
            "confidence_bucket": "high",
            "decision_status": "approved",
            "confidence": 0.85,
            "approved": True,
            "accepted_at": "2026-03-15T13:00:00Z",
            "canonical_version": 1,
            "event_hash": "",
            "leaf_hash": "",
            "leaf_index": 0,
            "checkpoint_id": 2,
            "receipt_algorithm": "Ed25519",
            "receipt_key_id": "test-key-001",
            "receipt_signature": "",
            "receipt_payload": "",
        }
        entry["event_hash"] = self._build_event_hash(entry)
        entry["leaf_hash"] = self._hash_leaf(entry["event_hash"])
        receipt_payload = self._build_receipt_payload(entry)
        entry["receipt_payload"] = self._b64url(receipt_payload)
        entry["receipt_signature"] = self._b64url(ed25519_private_key.sign(receipt_payload))

        checkpoint = {
            "checkpoint_id": 2,
            "microblock_id": 2,
            "tree_size": 1,
            "root_hash": entry["leaf_hash"],
            "checkpoint_hash": "",
            "prev_checkpoint_hash": "",
            "signature_algorithm": "Ed25519",
            "signer_key_id": "test-key-001",
            "checkpoint_signature": "",
            "checkpoint_payload": "",
            "signed_at": "2026-03-15T14:00:00Z",
            "mmd_seconds": 30,
            "export_target": "",
            "export_uri": "",
            "export_status": "",
        }
        checkpoint_payload = self._build_checkpoint_payload(checkpoint)
        checkpoint["checkpoint_hash"] = self._hash_checkpoint_payload(checkpoint_payload)
        checkpoint["checkpoint_payload"] = self._b64url(checkpoint_payload)
        checkpoint["checkpoint_signature"] = self._b64url(ed25519_private_key.sign(checkpoint_payload))

        respx.get("https://vault.test/.well-known/jwks.json").mock(
            return_value=Response(200, json=jwks_response)
        )

        result = await client.averify_ledger_proof(
            entries=[entry],
            manifests=[checkpoint],
        )

        assert result.intact is True
        assert result.latest_manifest_hash == checkpoint["checkpoint_hash"]


# ──────────────────────────────────────────────────────────────────────
# Client lifecycle
# ──────────────────────────────────────────────────────────────────────


# ──────────────────────────────────────────────────────────────────────
# Retry behaviour
# ──────────────────────────────────────────────────────────────────────


class TestRetry:
    """Tests for automatic retry with exponential backoff."""

    @respx.mock
    def test_retries_on_connection_error_then_succeeds(
        self, vault_config_retry: VaultConfig, approved_response: dict
    ):
        client = BylawClient(config=vault_config_retry)
        route = respx.post("https://vault.test/request-clearance").mock(
            side_effect=[
                httpx.ConnectError("Connection refused"),
                httpx.ConnectError("Connection refused"),
                Response(200, json=approved_response),
            ]
        )

        request = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45})
        result = client.request_clearance(request)

        assert result.is_approved is True
        assert route.call_count == 3
        client.close()

    @respx.mock
    def test_retries_on_5xx_then_succeeds(
        self, vault_config_retry: VaultConfig, approved_response: dict
    ):
        client = BylawClient(config=vault_config_retry)
        respx.post("https://vault.test/request-clearance").mock(
            side_effect=[
                Response(503, text="Service Unavailable"),
                Response(503, text="Service Unavailable"),
                Response(200, json=approved_response),
            ]
        )

        request = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45})
        result = client.request_clearance(request)

        assert result.is_approved is True
        client.close()

    @respx.mock
    def test_raises_after_exhausting_retries(self, vault_config_retry: VaultConfig):
        client = BylawClient(config=vault_config_retry)
        respx.post("https://vault.test/request-clearance").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        request = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45})
        with pytest.raises(VaultConnectionError):
            client.request_clearance(request)
        client.close()

    @respx.mock
    def test_does_not_retry_on_4xx(self, vault_config_retry: VaultConfig):
        client = BylawClient(config=vault_config_retry)
        route = respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(400, text="Bad Request")
        )

        request = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45})
        with pytest.raises(VaultConnectionError):
            client.request_clearance(request)

        # 400 is not retryable — should only be called once
        assert route.call_count == 1
        client.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_async_retries_on_connection_error(
        self, vault_config_retry: VaultConfig, approved_response: dict
    ):
        client = BylawClient(config=vault_config_retry)
        respx.post("https://vault.test/request-clearance").mock(
            side_effect=[
                httpx.ConnectError("Connection refused"),
                Response(200, json=approved_response),
            ]
        )

        request = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45})
        result = await client.arequest_clearance(request)

        assert result.is_approved is True
        await client.aclose()


class TestClientLifecycle:
    """Tests for context manager and close behavior."""

    def test_sync_context_manager(self, vault_config: VaultConfig):
        with BylawClient(config=vault_config) as client:
            assert client.config.vault_url == "https://vault.test"

    @pytest.mark.asyncio
    async def test_async_context_manager(self, vault_config: VaultConfig):
        async with BylawClient(config=vault_config) as client:
            assert client.config.vault_url == "https://vault.test"

    def test_default_config(self):
        """Client should work with defaults (reads env)."""
        client = BylawClient()
        assert client.config.vault_url == "http://localhost:8000"
        client.close()
