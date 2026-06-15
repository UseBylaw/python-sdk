# Tests for the SDK-side decision cache (Milestone B3b).
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from httpx import Response

from ledgix_python import LedgixClient, VaultConfig
from ledgix_python.exceptions import ClearanceDeniedError, VaultConnectionError
from ledgix_python.models import ClearanceRequest, ClearanceResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_jwt(private_key: Ed25519PrivateKey, request_id: str = "req-mint-001") -> str:
    payload = {
        "sub": "clearance",
        "iss": "alcv-vault",
        "aud": "ledgix-sdk",
        "tool": "stripe_refund",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        "request_id": request_id,
    }
    return jwt.encode(payload, private_key, algorithm="EdDSA")


def _cache_config(**overrides) -> VaultConfig:
    return VaultConfig(
        vault_url="https://vault.test",
        vault_api_key="test-key",
        vault_timeout=5.0,
        verify_jwt=False,
        max_retries=0,
        agent_id="agent-1",
        session_id="sess-1",
        decision_cache_enabled=True,
        decision_cache_ttl_seconds=60.0,
        decision_cache_max_entries=100,
        **overrides,
    )


def _approved_body(token: str, policy_version_id: str = "pvid-001") -> dict:
    return {
        "status": "approved",
        "decision_status": "approved",
        "token": token,
        "reason": "Policy passed",
        "request_id": "req-original-001",
        "confidence_bucket": "extra_high",
        "minimum_confidence_bucket": "medium",
        "policy_version_id": policy_version_id,
        "policy_content_hash": "sha256:abc",
    }


def _mint_body(token: str, request_id: str = "req-mint-001") -> dict:
    return {
        "request_id": request_id,
        "token": token,
        "decision_status": "approved",
        "reason": "Policy passed",
    }


# ---------------------------------------------------------------------------
# Cache key tests
# ---------------------------------------------------------------------------

class TestBuildCacheKey:
    def test_key_stability(self):
        cfg = _cache_config()
        client = LedgixClient(config=cfg)
        req = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 50})
        key1 = client._build_cache_key(req)
        key2 = client._build_cache_key(req)
        assert key1 == key2
        client.close()

    def test_different_tool_names_produce_different_keys(self):
        cfg = _cache_config()
        client = LedgixClient(config=cfg)
        req1 = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 50})
        req2 = ClearanceRequest(tool_name="send_email", tool_args={"amount": 50})
        assert client._build_cache_key(req1) != client._build_cache_key(req2)
        client.close()

    def test_dict_key_order_invariant(self):
        cfg = _cache_config()
        client = LedgixClient(config=cfg)
        req1 = ClearanceRequest(tool_name="t", tool_args={"b": 2, "a": 1})
        req2 = ClearanceRequest(tool_name="t", tool_args={"a": 1, "b": 2})
        assert client._build_cache_key(req1) == client._build_cache_key(req2)
        client.close()

    def test_different_agent_id_produces_different_keys(self):
        cfg = _cache_config()
        client = LedgixClient(config=cfg)
        req1 = ClearanceRequest(tool_name="t", tool_args={}, agent_id="agent-A")
        req2 = ClearanceRequest(tool_name="t", tool_args={}, agent_id="agent-B")
        assert client._build_cache_key(req1) != client._build_cache_key(req2)
        client.close()

    def test_large_tool_args_returns_empty_key(self):
        cfg = _cache_config()
        client = LedgixClient(config=cfg)
        big_args = {"data": "x" * 70_000}
        req = ClearanceRequest(tool_name="t", tool_args=big_args)
        assert client._build_cache_key(req) == ""
        client.close()


# ---------------------------------------------------------------------------
# Sync cache hit / miss
# ---------------------------------------------------------------------------

class TestSyncCache:
    def test_cache_miss_then_hit(self, ed25519_private_key):
        token = _make_jwt(ed25519_private_key)
        mint_token = _make_jwt(ed25519_private_key, "req-mint-001")
        cfg = _cache_config()
        client = LedgixClient(config=cfg)

        with respx.mock(base_url="https://vault.test") as mock:
            clearance_route = mock.post("/request-clearance").mock(
                return_value=Response(200, json=_approved_body(token))
            )
            mint_route = mock.post("/mint-token").mock(
                return_value=Response(200, json=_mint_body(mint_token))
            )

            req = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 50})

            # First call — cache miss → calls /request-clearance
            r1 = client.request_clearance(req)
            assert r1.is_approved
            assert clearance_route.call_count == 1
            assert mint_route.call_count == 0

            # Second call — cache hit → calls /mint-token, NOT /request-clearance
            r2 = client.request_clearance(req)
            assert r2.is_approved
            assert clearance_route.call_count == 1
            assert mint_route.call_count == 1

        client.close()

    def test_denied_response_not_cached(self, ed25519_private_key):
        cfg = _cache_config()
        client = LedgixClient(config=cfg)

        denied = {
            "status": "denied",
            "decision_status": "denied",
            "token": None,
            "reason": "Denied",
            "request_id": "req-deny-001",
            "confidence_bucket": "high",
            "minimum_confidence_bucket": "medium",
        }
        req = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 9999})

        with respx.mock(base_url="https://vault.test") as mock:
            mock.post("/request-clearance").mock(return_value=Response(200, json=denied))
            with pytest.raises(ClearanceDeniedError):
                client.request_clearance(req)

        # Cache should be empty
        key = client._build_cache_key(req)
        assert client._cache_get(key) is None
        client.close()

    def test_response_without_policy_version_id_not_cached(self, ed25519_private_key):
        token = _make_jwt(ed25519_private_key)
        cfg = _cache_config()
        client = LedgixClient(config=cfg)

        no_pvid = {
            "status": "approved",
            "decision_status": "approved",
            "token": token,
            "reason": "ok",
            "request_id": "req-001",
            "confidence_bucket": "high",
            "minimum_confidence_bucket": "medium",
            "policy_version_id": None,
        }
        req = ClearanceRequest(tool_name="t", tool_args={})

        with respx.mock(base_url="https://vault.test") as mock:
            mock.post("/request-clearance").mock(return_value=Response(200, json=no_pvid))
            client.request_clearance(req)

        key = client._build_cache_key(req)
        assert client._cache_get(key) is None
        client.close()

    def test_clear_cache(self, ed25519_private_key):
        token = _make_jwt(ed25519_private_key)
        cfg = _cache_config()
        client = LedgixClient(config=cfg)

        req = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 50})

        with respx.mock(base_url="https://vault.test", assert_all_called=False) as mock:
            clearance_route = mock.post("/request-clearance").mock(
                return_value=Response(200, json=_approved_body(token))
            )

            client.request_clearance(req)
            assert clearance_route.call_count == 1

            client.clear_cache()

            client.request_clearance(req)
            assert clearance_route.call_count == 2  # cache miss after clear

        client.close()

    def test_cache_isolated_by_agent_id(self, ed25519_private_key):
        token_a = _make_jwt(ed25519_private_key, "req-a-001")
        token_b = _make_jwt(ed25519_private_key, "req-b-001")
        cfg = _cache_config()
        client = LedgixClient(config=cfg)

        req_a = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 50}, agent_id="agent-A")
        req_b = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 50}, agent_id="agent-B")

        with respx.mock(base_url="https://vault.test", assert_all_called=False) as mock:
            clearance_route = mock.post("/request-clearance").mock(
                side_effect=[
                    Response(200, json=_approved_body(token_a)),
                    Response(200, json=_approved_body(token_b)),
                ]
            )

            client.request_clearance(req_a)
            client.request_clearance(req_b)
            assert clearance_route.call_count == 2  # different keys — both misses

        client.close()

    def test_cache_disabled_by_default(self, ed25519_private_key):
        token = _make_jwt(ed25519_private_key)
        cfg = VaultConfig(
            vault_url="https://vault.test",
            vault_api_key="test-key",
            vault_timeout=5.0,
            verify_jwt=False,
            max_retries=0,
            # decision_cache_enabled defaults to False
        )
        client = LedgixClient(config=cfg)
        assert client._decision_cache is None

        req = ClearanceRequest(tool_name="t", tool_args={})

        with respx.mock(base_url="https://vault.test") as mock:
            route = mock.post("/request-clearance").mock(
                return_value=Response(200, json=_approved_body(token))
            )
            client.request_clearance(req)
            client.request_clearance(req)
            assert route.call_count == 2  # no caching

        client.close()

    def test_mint_token_vault_error_raises(self, ed25519_private_key):
        token = _make_jwt(ed25519_private_key)
        cfg = _cache_config()
        client = LedgixClient(config=cfg)
        req = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 50})

        with respx.mock(base_url="https://vault.test") as mock:
            mock.post("/request-clearance").mock(return_value=Response(200, json=_approved_body(token)))
            client.request_clearance(req)  # populate cache

            mock.post("/mint-token").mock(return_value=Response(500, json={"error": "oops"}))
            with pytest.raises(VaultConnectionError):
                client.request_clearance(req)

        client.close()


# ---------------------------------------------------------------------------
# Async cache hit / miss
# ---------------------------------------------------------------------------

class TestAsyncCache:
    async def test_async_cache_miss_then_hit(self, ed25519_private_key):
        token = _make_jwt(ed25519_private_key)
        mint_token = _make_jwt(ed25519_private_key, "req-mint-async-001")
        cfg = _cache_config()
        client = LedgixClient(config=cfg)

        async with respx.mock(base_url="https://vault.test") as mock:
            clearance_route = mock.post("/request-clearance").mock(
                return_value=Response(200, json=_approved_body(token))
            )
            mint_route = mock.post("/mint-token").mock(
                return_value=Response(200, json=_mint_body(mint_token))
            )

            req = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 50})

            r1 = await client.arequest_clearance(req)
            assert r1.is_approved
            assert clearance_route.call_count == 1
            assert mint_route.call_count == 0

            r2 = await client.arequest_clearance(req)
            assert r2.is_approved
            assert clearance_route.call_count == 1
            assert mint_route.call_count == 1

        await client.aclose()

    async def test_async_clear_cache(self, ed25519_private_key):
        token = _make_jwt(ed25519_private_key)
        cfg = _cache_config()
        client = LedgixClient(config=cfg)

        req = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 50})

        async with respx.mock(base_url="https://vault.test", assert_all_called=False) as mock:
            clearance_route = mock.post("/request-clearance").mock(
                return_value=Response(200, json=_approved_body(token))
            )

            await client.arequest_clearance(req)
            assert clearance_route.call_count == 1

            client.clear_cache()

            await client.arequest_clearance(req)
            assert clearance_route.call_count == 2

        await client.aclose()

    async def test_async_mint_token_vault_error_raises(self, ed25519_private_key):
        token = _make_jwt(ed25519_private_key)
        cfg = _cache_config()
        client = LedgixClient(config=cfg)
        req = ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 50})

        async with respx.mock(base_url="https://vault.test") as mock:
            mock.post("/request-clearance").mock(return_value=Response(200, json=_approved_body(token)))
            await client.arequest_clearance(req)

            mock.post("/mint-token").mock(return_value=Response(503, json={"error": "unavailable"}))
            with pytest.raises(VaultConnectionError):
                await client.arequest_clearance(req)

        await client.aclose()
