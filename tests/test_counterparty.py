"""Client-side counterparty extractor tests.

Mirrors the server-side chain in vault/internal/counterparty so the SDK
populates the same provider keys and account refs the Vault would derive
on its own (caller-supplied wins on both sides).
"""

from __future__ import annotations

from ledgix_python import ClearanceRequest, LedgixClient, VaultConfig
from ledgix_python.counterparty import extract


def test_extract_stripe_truncates_key() -> None:
    # ship-safe-ignore Generic API Key Assignment
    out = extract("stripe.create_charge", {"api_key": "sk_test_abcdefghij1234", "amount": 500})
    assert out["destination_provider"] == "stripe"
    assert out["destination_uri"] == "https://api.stripe.com"
    assert out["destination_account_ref"] == "sk_test_abcd"


def test_extract_bedrock_uses_model_id() -> None:
    out = extract("aws.bedrock_invoke", {"model_id": "anthropic.claude-sonnet-4-5-v1:0"})
    assert out["destination_provider"] == "aws-bedrock"
    assert out["destination_account_ref"] == "anthropic.claude-sonnet-4-5-v1:0"


def test_extract_generic_http_fallback() -> None:
    out = extract("internal.web_request", {"url": "https://api.notion.com/v1/pages"})
    assert out["destination_uri"] == "https://api.notion.com/v1/pages"
    assert out["destination_provider"] == "notion.com"


def test_extract_unknown_returns_empty() -> None:
    assert extract("internal.compute_thing", {"x": 1}) == {}


def test_extract_empty_tool_name_returns_empty() -> None:
    assert extract("", {"url": "https://api.openai.com"}) == {}


def test_enrich_request_fills_destination_when_missing() -> None:
    client = LedgixClient(VaultConfig(vault_url="http://localhost:8000"))
    req = ClearanceRequest(
        tool_name="stripe_charge",
        # ship-safe-ignore Generic API Key Assignment
        tool_args={"api_key": "sk_test_abcdefghij1234", "amount": 100},
    )
    enriched = client._enrich_request(req)
    assert enriched.destination_provider == "stripe"
    assert enriched.destination_uri == "https://api.stripe.com"
    assert enriched.destination_account_ref == "sk_test_abcd"


def test_enrich_request_caller_destination_wins_over_inference() -> None:
    client = LedgixClient(VaultConfig(vault_url="http://localhost:8000"))
    req = ClearanceRequest(
        tool_name="stripe_charge",
        # ship-safe-ignore Generic API Key Assignment
        tool_args={"api_key": "sk_test_abcdefghij1234"},
        destination_provider="custom-stripe-shim",
        destination_account_ref="acct_explicit",
    )
    enriched = client._enrich_request(req)
    assert enriched.destination_provider == "custom-stripe-shim"
    assert enriched.destination_account_ref == "acct_explicit"
    assert enriched.destination_uri == "https://api.stripe.com"


def test_enrich_request_unknown_tool_leaves_destination_unset() -> None:
    client = LedgixClient(VaultConfig(vault_url="http://localhost:8000"))
    req = ClearanceRequest(tool_name="internal.compute", tool_args={"x": 1})
    enriched = client._enrich_request(req)
    assert enriched.destination_provider is None
    assert enriched.destination_uri is None
    assert enriched.destination_account_ref is None
