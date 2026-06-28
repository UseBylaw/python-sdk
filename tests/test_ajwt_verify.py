"""A-JWT cross-side verification tests.

The fixtures in ``tests/ajwt_fixtures/`` are copied verbatim from the Vault
repo (``vault/internal/crypto/testdata/ajwt/``). They are a deterministic
golden set: a JWKS (Ed25519 public key, ``kid = vault-test-key-001``), a valid
A-JWT, an expired A-JWT, and ``expected.json`` carrying the canonical claims.

These tests prove the SDK can independently verify the exact bytes Vault emits,
using PyJWT (a hard dependency via ``PyJWT[crypto]``):

* the valid token verifies under EdDSA with ``aud = ledgix-sdk`` and its claims
  match ``expected.json`` exactly (including ``tool_args_hash``);
* the expired token raises ``ExpiredSignatureError``;
* a tampered token raises a signature/decode failure.

NOTE: the wire audience stays ``ledgix-sdk`` even after the Bylaw rebrand —
Vault validates against ``VAULT_JWT_AUDIENCE=ledgix-sdk``. Do not "fix" it.
"""

from __future__ import annotations

import json
from pathlib import Path

import jwt
import pytest
from jwt.algorithms import OKPAlgorithm

FIXTURE_DIR = Path(__file__).parent / "ajwt_fixtures"
AUDIENCE = "ledgix-sdk"
ALGORITHMS = ["EdDSA"]


def _read(name: str) -> str:
    return (FIXTURE_DIR / name).read_text().strip()


def _load_json(name: str):
    return json.loads(_read(name))


def _public_key():
    """Build the Ed25519 public key from the single JWK in jwks.json."""
    jwks = _load_json("jwks.json")
    jwk = jwks["keys"][0]
    return OKPAlgorithm.from_jwk(json.dumps(jwk))


def test_jwks_has_expected_kid():
    jwks = _load_json("jwks.json")
    expected = _load_json("expected.json")
    kids = [k["kid"] for k in jwks["keys"]]
    assert expected["kid"] in kids
    jwk = jwks["keys"][0]
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert jwk["alg"] == "EdDSA"


def test_valid_token_verifies_and_claims_match_expected():
    expected = _load_json("expected.json")
    token = _read("token_valid.jwt")

    claims = jwt.decode(
        token,
        key=_public_key(),
        algorithms=ALGORITHMS,
        audience=AUDIENCE,
    )

    exp_claims = expected["claims"]

    # Audience: decoded form may be a list; expected stores the scalar.
    aud = claims["aud"]
    if isinstance(aud, list):
        assert exp_claims["aud"] in aud
        assert AUDIENCE in aud
    else:
        assert aud == exp_claims["aud"]

    # Every non-aud claim in expected.json must match byte-for-byte.
    for key, value in exp_claims.items():
        if key == "aud":
            continue
        assert claims[key] == value, f"claim {key!r} mismatch"

    # Load-bearing values called out explicitly.
    assert claims["iss"] == expected["issuer"] == "alcv-vault"
    assert claims["tool_args_hash"] == expected["tool_args_hash"]
    assert claims["decision"] == "approved"


def test_valid_token_header_kid_matches_jwks():
    token = _read("token_valid.jwt")
    expected = _load_json("expected.json")
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "EdDSA"
    assert header["kid"] == expected["kid"]


def test_expired_token_raises_expired_signature():
    token = _read("token_expired.jwt")
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(
            token,
            key=_public_key(),
            algorithms=ALGORITHMS,
            audience=AUDIENCE,
        )


def test_expired_token_signature_is_otherwise_valid():
    """Confirm only `exp` is in the past: disabling exp verification succeeds."""
    token = _read("token_expired.jwt")
    expected = _load_json("expected.json")
    claims = jwt.decode(
        token,
        key=_public_key(),
        algorithms=ALGORITHMS,
        audience=AUDIENCE,
        options={"verify_exp": False},
    )
    assert claims["jti"] == expected["expired_jti"]
    assert claims["exp"] == expected["expired_exp_unix"]


def _tamper_payload(token: str) -> str:
    """Flip a character in the payload segment to break the signature."""
    header, payload, signature = token.split(".")
    # Flip the first char of the payload to a different base64url char.
    first = payload[0]
    replacement = "B" if first != "B" else "C"
    tampered_payload = replacement + payload[1:]
    return f"{header}.{tampered_payload}.{signature}"


def test_tampered_token_raises_signature_error():
    token = _read("token_valid.jwt")
    tampered = _tamper_payload(token)
    assert tampered != token
    with pytest.raises((jwt.InvalidSignatureError, jwt.DecodeError)):
        jwt.decode(
            tampered,
            key=_public_key(),
            algorithms=ALGORITHMS,
            audience=AUDIENCE,
        )


def test_wrong_audience_rejected():
    """A token minted for ledgix-sdk must not verify under a different audience."""
    token = _read("token_valid.jwt")
    with pytest.raises(jwt.InvalidAudienceError):
        jwt.decode(
            token,
            key=_public_key(),
            algorithms=ALGORITHMS,
            audience="some-other-audience",
        )
