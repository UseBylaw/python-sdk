"""Tests for A-JWT jti replay detection."""
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
from bylaw_python.exceptions import ReplayDetectedError, TokenVerificationError


def make_jwks(private_key: Ed25519PrivateKey, kid: str = "test-key") -> dict:
    public_key = private_key.public_key()
    jwk = json.loads(jwt.algorithms.OKPAlgorithm.to_jwk(public_key))
    jwk["use"] = "sig"
    jwk["kid"] = kid
    return {"keys": [jwk]}


def make_token(
    private_key: Ed25519PrivateKey,
    kid: str = "test-key",
    jti: str | None = None,
    include_jti: bool = True,
) -> str:
    payload: dict = {
        "sub": "clearance",
        "iss": "alcv-vault",
        "aud": "bylaw-sdk",
        "tool": "stripe_refund",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    if include_jti:
        payload["jti"] = jti or str(uuid.uuid4())
    return jwt.encode(payload, private_key, algorithm="EdDSA", headers={"kid": kid})


@pytest.fixture
def private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def config(private_key: Ed25519PrivateKey) -> VaultConfig:
    return VaultConfig(
        vault_url="https://vault.test",
        vault_api_key="key",
        verify_jwt=True,
        jwt_issuer="alcv-vault",
        jwt_audience="bylaw-sdk",
        max_retries=0,
    )


@pytest.fixture
def client_with_jwks(private_key: Ed25519PrivateKey, config: VaultConfig):
    jwks = make_jwks(private_key)
    c = BylawClient(config=config)
    c._jwks_cache = jwks
    c._index_jwks_by_kid(jwks)
    yield c
    c.close()


class TestReplayDetection:
    def test_same_token_twice_raises(
        self, client_with_jwks: BylawClient, private_key: Ed25519PrivateKey
    ) -> None:
        """Presenting the same A-JWT twice raises ReplayDetectedError on the second call."""
        token = make_token(private_key, jti="unique-jti-1")
        client_with_jwks.verify_token(token)  # first call: OK

        with pytest.raises(ReplayDetectedError) as exc_info:
            client_with_jwks.verify_token(token)  # second call: replay
        assert "unique-jti-1" in str(exc_info.value)

    def test_different_tokens_both_succeed(
        self, client_with_jwks: BylawClient, private_key: Ed25519PrivateKey
    ) -> None:
        """Two tokens with different jtis both verify successfully."""
        token_a = make_token(private_key, jti="jti-a")
        token_b = make_token(private_key, jti="jti-b")
        client_with_jwks.verify_token(token_a)
        client_with_jwks.verify_token(token_b)  # different jti — should not raise

    def test_missing_jti_raises(
        self, client_with_jwks: BylawClient, private_key: Ed25519PrivateKey
    ) -> None:
        """A token without a jti claim is rejected (fail-closed)."""
        token = make_token(private_key, include_jti=False)
        with pytest.raises(TokenVerificationError, match="jti"):
            client_with_jwks.verify_token(token)

    def test_replay_detected_error_is_token_verification_error(self) -> None:
        """ReplayDetectedError is a TokenVerificationError for easy catching."""
        err = ReplayDetectedError("some-jti")
        assert isinstance(err, TokenVerificationError)
        assert "some-jti" in str(err)
