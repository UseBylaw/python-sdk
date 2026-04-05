# Ledgix ALCV — Enforcement Layer
# Decorator and context manager for intercepting tool calls

from __future__ import annotations

import asyncio
import contextvars
import functools
import inspect
from typing import Any, Callable, TypeVar

from .client import LedgixClient
from .config import VaultConfig
from .exceptions import ClearanceDeniedError
from .models import ClearanceRequest, ClearanceResponse

F = TypeVar("F", bound=Callable[..., Any])

# ---------------------------------------------------------------------------
# Global singleton & context variable
# ---------------------------------------------------------------------------

_default_client: LedgixClient | None = None
_current_clearance: contextvars.ContextVar[ClearanceResponse | None] = contextvars.ContextVar(
    "_ledgix_clearance", default=None
)


def configure(config: VaultConfig | None = None, **kwargs: Any) -> LedgixClient:
    """Configure the global Ledgix client.

    Call this once at application startup.  All subsequent calls to
    :func:`enforce` will use this client automatically.

    Keyword arguments are forwarded to :class:`~ledgix_python.VaultConfig`
    when no explicit *config* object is provided::

        import ledgix_python as ledgix

        ledgix.configure(agent_id="finance-agent")

    Args:
        config: Optional pre-built :class:`~ledgix_python.VaultConfig`.
        **kwargs: Config overrides passed to ``VaultConfig`` when *config* is
            ``None``.

    Returns:
        The newly created :class:`~ledgix_python.LedgixClient`.
    """
    global _default_client
    if config is None:
        config = VaultConfig(**kwargs)
    _default_client = LedgixClient(config)
    return _default_client


def _get_default_client() -> LedgixClient:
    """Return the global client, raising if :func:`configure` was never called."""
    if _default_client is None:
        raise RuntimeError(
            "No Ledgix client configured. Call ledgix.configure() at startup "
            "before using @ledgix.enforce()."
        )
    return _default_client


def current_clearance() -> ClearanceResponse | None:
    """Return the :class:`~ledgix_python.ClearanceResponse` for the current call.

    Returns ``None`` when called outside an :func:`enforce`-wrapped function.
    """
    return _current_clearance.get()


def current_token() -> str | None:
    """Return the A-JWT token for the current call.

    Returns ``None`` when called outside an :func:`enforce`-wrapped function or
    when the clearance did not include a token.
    """
    clearance = _current_clearance.get()
    if clearance is None:
        return None
    return clearance.token


# ---------------------------------------------------------------------------
# New low-code decorator: enforce()
# ---------------------------------------------------------------------------

def enforce(
    *,
    tool_name: str | None = None,
    policy_id: str | None = None,
    context: dict[str, Any] | None = None,
) -> Callable[[F], F]:
    """Decorator that enforces Vault clearance before a function executes.

    Requires :func:`configure` to have been called at startup.  The A-JWT
    token is stored in a context variable and can be retrieved inside the
    decorated function via :func:`current_token`::

        import ledgix_python as ledgix

        ledgix.configure(agent_id="finance-agent")

        @ledgix.enforce(tool_name="stripe_refund")
        def process_refund(amount: float, reason: str):
            token = ledgix.current_token()
            stripe.refund(amount=amount, metadata={"vault_token": token})

    Works with both sync and async functions.  Unlike :func:`vault_enforce`,
    no ``_clearance`` kwarg is injected — the function signature is untouched.
    """

    def decorator(func: F) -> F:
        resolved_name = tool_name or func.__name__

        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                client = _get_default_client()
                request = ClearanceRequest(
                    tool_name=resolved_name,
                    tool_args=_extract_tool_args(func, args, kwargs),
                    agent_id=client.config.agent_id,
                    session_id=client.config.session_id,
                    context={**(context or {}), **({"policy_id": policy_id} if policy_id else {})},
                )
                clearance = await client.arequest_clearance(request)
                token = _current_clearance.set(clearance)
                try:
                    return await func(*args, **kwargs)
                finally:
                    _current_clearance.reset(token)

            return async_wrapper  # type: ignore[return-value]

        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                client = _get_default_client()
                request = ClearanceRequest(
                    tool_name=resolved_name,
                    tool_args=_extract_tool_args(func, args, kwargs),
                    agent_id=client.config.agent_id,
                    session_id=client.config.session_id,
                    context={**(context or {}), **({"policy_id": policy_id} if policy_id else {})},
                )
                clearance = client.request_clearance(request)
                token = _current_clearance.set(clearance)
                try:
                    return func(*args, **kwargs)
                finally:
                    _current_clearance.reset(token)

            return sync_wrapper  # type: ignore[return-value]

    return decorator


# ---------------------------------------------------------------------------
# Original explicit decorator: vault_enforce()  (unchanged)
# ---------------------------------------------------------------------------

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

    .. note::
        Prefer :func:`enforce` for new code — it requires no changes to the
        function signature and uses the global client set by :func:`configure`.
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
    """Best-effort extraction of function arguments as a dict for the clearance request.

    Skips ``self``, private parameters (prefixed with ``_``), ``*args``, and
    ``**kwargs`` captures so only named, user-visible parameters are included.
    """
    try:
        sig = inspect.signature(func)
        bound = sig.bind_partial(*args, **kwargs)
        bound.apply_defaults()
        result: dict[str, Any] = {}
        for name, value in bound.arguments.items():
            if name.startswith("_") or name == "self":
                continue
            param = sig.parameters[name]
            if param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
                continue
            result[name] = value
        return result
    except (TypeError, ValueError):
        return {k: v for k, v in kwargs.items() if not k.startswith("_")}
