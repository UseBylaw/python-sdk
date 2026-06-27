"""Tests for JWKS kid matching and automatic refetch on key rotation."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from httpx import Response

from bylaw_python import BylawClient, VaultConfig
from bylaw_python.exceptions import TokenVerificationError


def make_jwks(private_key: Ed25519PrivateKey, kid: str) -> dict:
    public_key = private_key.public_key()
    jwk = json.loads(jwt.algorithms.OKPAlgorithm.to_jwk(public_key))
    jwk["use"] = "sig"
    jwk["kid"] = kid
    return {"keys": [jwk]}


def make_token(
    private_key: Ed25519PrivateKey,
    kid: str,
    jti: str | None = None,
    audience: str = "bylaw-sdk",
) -> str:
    payload = {
        "sub": "clearance",
        "iss": "alcv-vault",
        "aud": audience,
        "tool": "stripe_refund",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        "jti": jti or str(uuid.uuid4()),
    }
    return jwt.encode(payload, private_key, algorithm="EdDSA", headers={"kid": kid})


@pytest.fixture
def config() -> VaultConfig:
    return VaultConfig(
        vault_url="https://vault.test",
        vault_api_key="key",
        verify_jwt=True,
        jwt_issuer="alcv-vault",
        jwt_audience="bylaw-sdk",
        max_retries=0,
        jwks_ttl_seconds=300,
    )


def test_verify_token_with_kid_matching(config: VaultConfig) -> None:
    """Token signed with key k1 verifies when JWKS exposes k1."""
    key1 = Ed25519PrivateKey.generate()
    jwks = make_jwks(key1, "k1")
    token = make_token(key1, "k1")

    with respx.mock(base_url="https://vault.test") as mock:
        mock.get("/.well-known/jwks.json").mock(return_value=Response(200, json=jwks))
        client = BylawClient(config=config)
        decoded = client.verify_token(token)
        assert decoded["sub"] == "clearance"


def test_default_audience_matches_current_vault() -> None:
    """Default verification accepts Vault A-JWTs until the server audience rebrands."""
    key = Ed25519PrivateKey.generate()
    jwks = make_jwks(key, "k1")
    token = make_token(key, "k1", audience="bylaw-sdk")
    config = VaultConfig(
        vault_url="https://vault.test",
        vault_api_key="key",
        verify_jwt=True,
        jwt_issuer="alcv-vault",
        max_retries=0,
    )

    with respx.mock(base_url="https://vault.test") as mock:
        mock.get("/.well-known/jwks.json").mock(return_value=Response(200, json=jwks))
        client = BylawClient(config=config)
        decoded = client.verify_token(token)
        assert decoded["aud"] == "bylaw-sdk"


def test_verify_refetches_jwks_on_kid_miss(config: VaultConfig) -> None:
    """When the token's kid is not in the cached JWKS, the SDK refetches once."""
    key1 = Ed25519PrivateKey.generate()
    key2 = Ed25519PrivateKey.generate()
    old_jwks = make_jwks(key1, "k1")
    new_jwks = make_jwks(key2, "k2")
    token_k2 = make_token(key2, "k2")

    fetch_count = 0

    def jwks_handler(request):
        nonlocal fetch_count
        fetch_count += 1
        # First call: return old JWKS (only k1); second call: return new JWKS (k2).
        return Response(200, json=old_jwks if fetch_count == 1 else new_jwks)

    with respx.mock(base_url="https://vault.test") as mock:
        mock.get("/.well-known/jwks.json").mock(side_effect=jwks_handler)
        client = BylawClient(config=config)
        # Manually pre-populate cache with old JWKS to simulate a cached state.
        client.fetch_jwks()  # fetch_count=1: old JWKS, only k1
        assert fetch_count == 1

        # Verifying a token signed with k2 should trigger a refetch.
        decoded = client.verify_token(token_k2)
        assert fetch_count == 2, "expected JWKS refetch on kid miss"
        assert decoded["sub"] == "clearance"


def test_verify_unknown_kid_after_refetch_raises(config: VaultConfig) -> None:
    """If the kid is still missing after a refetch, raise TokenVerificationError."""
    key1 = Ed25519PrivateKey.generate()
    key2 = Ed25519PrivateKey.generate()
    old_jwks = make_jwks(key1, "k1")
    token_k2 = make_token(key2, "k2")

    with respx.mock(base_url="https://vault.test") as mock:
        # Always return old JWKS — k2 never appears.
        mock.get("/.well-known/jwks.json").mock(return_value=Response(200, json=old_jwks))
        client = BylawClient(config=config)
        client.fetch_jwks()

        with pytest.raises(TokenVerificationError, match="k2"):
            client.verify_token(token_k2)
