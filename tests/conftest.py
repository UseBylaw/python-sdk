# Ledgix ALCV — Test Fixtures
# Shared fixtures for the entire test suite

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from httpx import Response

from ledgix_python import LedgixClient, VaultConfig


# ──────────────────────────────────────────────────────────────────────
# Crypto fixtures
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def ed25519_private_key() -> Ed25519PrivateKey:
    """Generate a fresh Ed25519 private key for testing."""
    return Ed25519PrivateKey.generate()


@pytest.fixture
def ed25519_public_key(ed25519_private_key: Ed25519PrivateKey):
    return ed25519_private_key.public_key()


@pytest.fixture
def sample_jwt(ed25519_private_key: Ed25519PrivateKey) -> str:
    """Create a valid A-JWT for testing."""
    payload = {
        "sub": "clearance",
        "iss": "alcv-vault",
        "aud": "ledgix-sdk",
        "tool": "stripe_refund",
        "amount": 45.0,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        "request_id": "test-req-001",
    }
    return jwt.encode(payload, ed25519_private_key, algorithm="EdDSA")


@pytest.fixture
def expired_jwt(ed25519_private_key: Ed25519PrivateKey) -> str:
    """Create an expired A-JWT for testing."""
    payload = {
        "sub": "clearance",
        "iss": "alcv-vault",
        "aud": "ledgix-sdk",
        "tool": "stripe_refund",
        "iat": datetime.now(timezone.utc) - timedelta(hours=1),
        "exp": datetime.now(timezone.utc) - timedelta(minutes=5),
        "request_id": "test-req-expired",
    }
    return jwt.encode(payload, ed25519_private_key, algorithm="EdDSA")


@pytest.fixture
def jwks_response(ed25519_private_key: Ed25519PrivateKey) -> dict:
    """Build a JWKS response from the test key."""
    public_key = ed25519_private_key.public_key()
    jwk = json.loads(jwt.algorithms.OKPAlgorithm.to_jwk(public_key))
    jwk["use"] = "sig"
    jwk["kid"] = "test-key-001"
    return {"keys": [jwk]}


# ──────────────────────────────────────────────────────────────────────
# Config & client fixtures
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def vault_config() -> VaultConfig:
    return VaultConfig(
        vault_url="https://vault.test",
        vault_api_key="test-api-key",
        vault_timeout=5.0,
        verify_jwt=False,
        jwt_issuer="alcv-vault",
        jwt_audience="ledgix-sdk",
        agent_id="test-agent",
        session_id="test-session",
    )


@pytest.fixture
def vault_config_with_jwt() -> VaultConfig:
    return VaultConfig(
        vault_url="https://vault.test",
        vault_api_key="test-api-key",
        vault_timeout=5.0,
        verify_jwt=True,
        jwt_issuer="alcv-vault",
        jwt_audience="ledgix-sdk",
        agent_id="test-agent",
        session_id="test-session",
    )


@pytest.fixture
def client(vault_config: VaultConfig) -> LedgixClient:
    c = LedgixClient(config=vault_config)
    yield c
    c.close()


@pytest.fixture
def client_with_jwt(vault_config_with_jwt: VaultConfig) -> LedgixClient:
    c = LedgixClient(config=vault_config_with_jwt)
    yield c
    c.close()


# ──────────────────────────────────────────────────────────────────────
# Vault API mock responses
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def approved_response(sample_jwt: str) -> dict:
    return {
        "status": "approved",
        "approved": True,
        "token": sample_jwt,
        "reason": "Policy check passed",
        "request_id": "req-001",
    }


@pytest.fixture
def denied_response() -> dict:
    return {
        "status": "denied",
        "approved": False,
        "token": None,
        "reason": "Amount exceeds $100 limit",
        "request_id": "req-002",
    }


@pytest.fixture
def policy_response() -> dict:
    return {
        "policy_id": "refund-policy",
        "status": "registered",
        "message": "Policy registered successfully",
    }
