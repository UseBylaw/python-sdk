# Ledgix ALCV — Enforcement Layer
# Decorator and context manager for intercepting tool calls

from __future__ import annotations

import asyncio
import functools
import inspect
from typing import Any, Callable, TypeVar

from .client import LedgixClient
from .exceptions import ClearanceDeniedError
from .models import ClearanceRequest, ClearanceResponse

F = TypeVar("F", bound=Callable[..., Any])


class VaultContext:
    """Context manager that requests clearance before executing a block.

    Sync usage::

        with VaultContext(client, "stripe_refund", {"amount": 45}) as ctx:
            # ctx.clearance contains the ClearanceResponse
            execute_refund(ctx.clearance.token)

    Async usage::

        async with VaultContext(client, "stripe_refund", {"amount": 45}) as ctx:
            execute_refund(ctx.clearance.token)
    """

    def __init__(
        self,
        client: LedgixClient,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        *,
        context: dict[str, Any] | None = None,
        policy_id: str | None = None,
    ) -> None:
        self.client = client
        self.tool_name = tool_name
        self.tool_args = tool_args or {}
        self.context = context or {}
        self.policy_id = policy_id
        self.clearance: ClearanceResponse | None = None

    def _build_request(self) -> ClearanceRequest:
        ctx = {**self.context}
        if self.policy_id:
            ctx["policy_id"] = self.policy_id
        return ClearanceRequest(
            tool_name=self.tool_name,
            tool_args=self.tool_args,
            agent_id=self.client.config.agent_id,
            session_id=self.client.config.session_id,
            context=ctx,
        )

    # Sync context manager
    def __enter__(self) -> VaultContext:
        request = self._build_request()
        self.clearance = self.client.request_clearance(request)
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    # Async context manager
    async def __aenter__(self) -> VaultContext:
        request = self._build_request()
        self.clearance = await self.client.arequest_clearance(request)
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass


def vault_enforce(
    client: LedgixClient,
    *,
    tool_name: str | None = None,
    policy_id: str | None = None,
    context: dict[str, Any] | None = None,
) -> Callable[[F], F]:
    """Decorator that enforces Vault clearance before a function executes.

    Works with both sync and async functions automatically.

    Usage::

        @vault_enforce(client, tool_name="stripe_refund")
        def process_refund(amount: float, reason: str):
            # This only runs if the Vault approves
            stripe.refund(amount=amount, reason=reason)

        @vault_enforce(client, tool_name="stripe_refund")
        async def async_process_refund(amount: float, reason: str):
            await stripe.refund(amount=amount, reason=reason)

    The decorated function receives an injected ``_clearance`` keyword
    argument containing the ``ClearanceResponse`` (with the A-JWT token).
    """

    def decorator(func: F) -> F:
        resolved_name = tool_name or func.__name__

        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                request = ClearanceRequest(
                    tool_name=resolved_name,
                    tool_args=_extract_tool_args(func, args, kwargs),
                    agent_id=client.config.agent_id,
                    session_id=client.config.session_id,
                    context={**(context or {}), **({"policy_id": policy_id} if policy_id else {})},
                )
                clearance = await client.arequest_clearance(request)
                kwargs["_clearance"] = clearance
                return await func(*args, **kwargs)

            return async_wrapper  # type: ignore[return-value]

        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                request = ClearanceRequest(
                    tool_name=resolved_name,
                    tool_args=_extract_tool_args(func, args, kwargs),
                    agent_id=client.config.agent_id,
                    session_id=client.config.session_id,
                    context={**(context or {}), **({"policy_id": policy_id} if policy_id else {})},
                )
                clearance = client.request_clearance(request)
                kwargs["_clearance"] = clearance
                return func(*args, **kwargs)

            return sync_wrapper  # type: ignore[return-value]

    return decorator


def _extract_tool_args(
    func: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> dict[str, Any]:
    """Best-effort extraction of function arguments as a dict for the clearance request."""
    try:
        sig = inspect.signature(func)
        bound = sig.bind_partial(*args, **kwargs)
        bound.apply_defaults()
        # Filter out internal kwargs
        return {
            k: v
            for k, v in bound.arguments.items()
            if not k.startswith("_") and k != "self"
        }
    except Exception:
        # Fallback: just return kwargs
        return {k: v for k, v in kwargs.items() if not k.startswith("_")}
