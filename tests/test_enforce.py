# Bylaw ALCV — Enforce Tests
# Tests for the decorator and context manager

from __future__ import annotations

import pytest
import respx
from httpx import Response

import bylaw_python as bylaw
from bylaw_python import BylawClient
from bylaw_python.enforce import VaultContext, vault_enforce
from bylaw_python.exceptions import ClearanceDeniedError

# ──────────────────────────────────────────────────────────────────────
# Decorator tests — sync
# ──────────────────────────────────────────────────────────────────────


class TestVaultEnforceSync:
    """Tests for @vault_enforce with sync functions."""

    @respx.mock
    def test_approved_calls_function(self, client: BylawClient, approved_response: dict):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        @vault_enforce(client, tool_name="my_tool")
        def my_tool(x: int, y: int, **kwargs):
            return x + y

        result = my_tool(3, 4)
        assert result == 7

    @respx.mock
    def test_denied_raises_error(self, client: BylawClient, denied_response: dict):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=denied_response)
        )

        @vault_enforce(client, tool_name="my_tool")
        def my_tool(x: int, **kwargs):
            return x

        with pytest.raises(ClearanceDeniedError):
            my_tool(42)

    @respx.mock
    def test_clearance_injected(self, client: BylawClient, approved_response: dict):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        @vault_enforce(client, tool_name="my_tool")
        def my_tool(x: int, **kwargs):
            clearance = kwargs.get("_clearance")
            return clearance.token

        result = my_tool(1)
        assert result is not None  # The A-JWT token

    @respx.mock
    def test_uses_function_name_as_default(self, client: BylawClient, approved_response: dict):
        route = respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        @vault_enforce(client)
        def stripe_refund(amount: float, **kwargs):
            return amount

        stripe_refund(50.0)

        import json
        body = json.loads(route.calls[0].request.content)
        assert body["tool_name"] == "stripe_refund"

    @respx.mock
    def test_extracts_tool_args(self, client: BylawClient, approved_response: dict):
        route = respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        @vault_enforce(client, tool_name="refund")
        def process_refund(amount: float, reason: str, **kwargs):
            return "done"

        process_refund(99.99, "late delivery")

        import json
        body = json.loads(route.calls[0].request.content)
        assert body["tool_args"]["amount"] == 99.99
        assert body["tool_args"]["reason"] == "late delivery"

    @respx.mock
    def test_with_policy_id(self, client: BylawClient, approved_response: dict):
        route = respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        @vault_enforce(client, tool_name="refund", policy_id="refund-policy")
        def process_refund(amount: float, **kwargs):
            return "done"

        process_refund(50.0)

        import json
        body = json.loads(route.calls[0].request.content)
        assert body["context"]["policy_id"] == "refund-policy"

    @respx.mock
    def test_explicit_none_gdpr_overrides_context(
        self,
        client: BylawClient,
        approved_response: dict,
    ):
        route = respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        @vault_enforce(
            client,
            tool_name="customer_export",
            context={
                "purpose": "billing",
                "data_categories": ["customer_email"],
                "dataset_ref": "prod_customer_support_kb",
            },
            purpose=None,
            data_categories=None,
            dataset_ref=None,
        )
        def customer_export(**kwargs):
            return "done"

        customer_export()

        import json
        body = json.loads(route.calls[0].request.content)
        assert "purpose" not in body["context"]
        assert "data_categories" not in body["context"]
        assert "dataset_ref" not in body["context"]


# ──────────────────────────────────────────────────────────────────────
# Low-code decorator tests
# ──────────────────────────────────────────────────────────────────────


class TestEnforce:
    """Tests for @enforce with the configured default client."""

    @respx.mock
    def test_explicit_none_gdpr_overrides_context(
        self,
        vault_config,
        approved_response: dict,
    ):
        route = respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )
        bylaw.configure(vault_config)

        @bylaw.enforce(
            tool_name="customer_export",
            context={
                "purpose": "billing",
                "data_categories": ["customer_email"],
                "dataset_ref": "prod_customer_support_kb",
            },
            purpose=None,
            data_categories=None,
            dataset_ref=None,
        )
        def customer_export():
            return bylaw.current_token()

        assert customer_export() == approved_response["token"]

        import json
        body = json.loads(route.calls[0].request.content)
        assert "purpose" not in body["context"]
        assert "data_categories" not in body["context"]
        assert "dataset_ref" not in body["context"]


# ──────────────────────────────────────────────────────────────────────
# Decorator tests — async
# ──────────────────────────────────────────────────────────────────────


class TestVaultEnforceAsync:
    """Tests for @vault_enforce with async functions."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_approved_async(self, client: BylawClient, approved_response: dict):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        @vault_enforce(client, tool_name="my_tool")
        async def my_tool(x: int, **kwargs):
            return x * 2

        result = await my_tool(5)
        assert result == 10

    @respx.mock
    @pytest.mark.asyncio
    async def test_denied_async(self, client: BylawClient, denied_response: dict):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=denied_response)
        )

        @vault_enforce(client, tool_name="my_tool")
        async def my_tool(x: int, **kwargs):
            return x

        with pytest.raises(ClearanceDeniedError):
            await my_tool(42)


# ──────────────────────────────────────────────────────────────────────
# Context manager tests
# ──────────────────────────────────────────────────────────────────────


class TestVaultContext:
    """Tests for VaultContext (sync + async context manager)."""

    @respx.mock
    def test_sync_context_approved(self, client: BylawClient, approved_response: dict):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        with VaultContext(client, "refund_tool", {"amount": 45}) as ctx:
            assert ctx.clearance is not None
            assert ctx.clearance.is_approved is True
            assert ctx.clearance.token is not None

    @respx.mock
    def test_sync_context_denied(self, client: BylawClient, denied_response: dict):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=denied_response)
        )

        with pytest.raises(ClearanceDeniedError), VaultContext(client, "refund_tool", {"amount": 5000}):
            pass  # Should never reach here

    @respx.mock
    @pytest.mark.asyncio
    async def test_async_context_approved(self, client: BylawClient, approved_response: dict):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        async with VaultContext(client, "refund_tool", {"amount": 45}) as ctx:
            assert ctx.clearance is not None
            assert ctx.clearance.is_approved is True

    @respx.mock
    @pytest.mark.asyncio
    async def test_async_context_denied(self, client: BylawClient, denied_response: dict):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=denied_response)
        )

        with pytest.raises(ClearanceDeniedError):
            async with VaultContext(client, "refund_tool", {"amount": 5000}):
                pass

    @respx.mock
    def test_context_with_policy_id(self, client: BylawClient, approved_response: dict):
        route = respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        with VaultContext(client, "refund_tool", {"amount": 45}, policy_id="refund-policy"):
            pass

        import json
        body = json.loads(route.calls[0].request.content)
        assert body["context"]["policy_id"] == "refund-policy"

    @respx.mock
    def test_explicit_none_gdpr_overrides_context(
        self,
        client: BylawClient,
        approved_response: dict,
    ):
        route = respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        with VaultContext(
            client,
            "customer_export",
            {},
            context={
                "purpose": "billing",
                "data_categories": ["customer_email"],
                "dataset_ref": "prod_customer_support_kb",
            },
            purpose=None,
            data_categories=None,
            dataset_ref=None,
        ):
            pass

        import json
        body = json.loads(route.calls[0].request.content)
        assert "purpose" not in body["context"]
        assert "data_categories" not in body["context"]
        assert "dataset_ref" not in body["context"]
