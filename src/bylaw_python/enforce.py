# Bylaw ALCV — Enforcement Layer
# Decorator and context manager for intercepting tool calls

from __future__ import annotations

import asyncio
import contextvars
import functools
import importlib
import inspect
import logging
import pkgutil
import sys
import types
from pathlib import Path
from typing import Any, Callable, TypeVar

from .client import BylawClient
from .config import VaultConfig
from .evidence import aguard_action, aobserve_source, guard_action, observe_source
from .exceptions import ClearanceDeniedError, ReviewPendingError
from .manifest import EvidenceRule, Manifest, ManifestRule, load_manifest
from .models import ClearanceRequest, ClearanceResponse
from .pending import PendingApproval

F = TypeVar("F", bound=Callable[..., Any])

_evidence_log = logging.getLogger("bylaw.evidence")

# ---------------------------------------------------------------------------
# Global singleton & context variable
# ---------------------------------------------------------------------------

_default_client: BylawClient | None = None
_current_clearance: contextvars.ContextVar[ClearanceResponse | None] = contextvars.ContextVar(
    "_bylaw_clearance", default=None
)
_manifest: Manifest | None = None


def configure(config: VaultConfig | None = None, **kwargs: Any) -> BylawClient:
    """Configure the global Bylaw client.

    Call this once at application startup.  All subsequent calls to
    :func:`enforce` will use this client automatically.

    Keyword arguments are forwarded to :class:`~bylaw_python.VaultConfig`
    when no explicit *config* object is provided::

        import bylaw_python as bylaw

        bylaw.configure(agent_id="finance-agent")

    Args:
        config: Optional pre-built :class:`~bylaw_python.VaultConfig`.
        **kwargs: Config overrides passed to ``VaultConfig`` when *config* is
            ``None``.

    Returns:
        The newly created :class:`~bylaw_python.BylawClient`.
    """
    global _default_client
    if config is None:
        config = VaultConfig(**kwargs)
    _default_client = BylawClient(config)
    return _default_client


def _get_default_client() -> BylawClient:
    """Return the global client, raising if :func:`configure` was never called."""
    if _default_client is None:
        raise RuntimeError(
            "No Bylaw client configured. Call bylaw.configure() at startup "
            "before using @bylaw.enforce()."
        )
    return _default_client


def current_clearance() -> ClearanceResponse | None:
    """Return the :class:`~bylaw_python.ClearanceResponse` for the current call.

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
# Manifest-driven auto-instrumentation
# ---------------------------------------------------------------------------

def auto_instrument(
    module: types.ModuleType,
    manifest: str | Path | dict[str, Any] | Manifest | None = None,
    recurse: bool = False,
) -> list[str]:
    """Scan modules and wrap matching functions according to a manifest.

    Call once at startup after :func:`configure`::

        import tools
        import bylaw_python as bylaw

        bylaw.configure(agent_id="my-agent")
        bylaw.auto_instrument(tools)          # reads bylaw.yaml from CWD

    Or point at a specific manifest::

        bylaw.auto_instrument(tools, manifest="config/bylaw.yaml")
        bylaw.auto_instrument(tools, manifest={"enforce": [
            {"tool": "stripe_*", "policy_id": "financial-high-risk"},
        ]})

    Only functions *defined* in the scanned module are wrapped — functions
    imported into it are skipped.  If you have tools outside the scanned
    modules use the :func:`tool` decorator as an escape hatch.

    .. warning::
        Call ``auto_instrument`` before other modules import the tool functions.
        Monkey-patching updates the module namespace, but existing references
        held by already-imported modules will not be retroactively wrapped.

    Args:
        module: Module or package (when *recurse* is ``True``) to scan.
        manifest: Path to a manifest file, an inline ``dict``, a pre-built
            :class:`~bylaw_python.Manifest`, or ``None`` to auto-discover
            ``bylaw.yaml`` / ``bylaw.yml`` / ``bylaw.json`` in the CWD.
        recurse: If ``True``, also scan sub-packages of any package module.

    Returns:
        Sorted list of qualified names that were wrapped,
        e.g. ``["tools.stripe_payment", "tools.issue_refund"]``.
    """
    global _manifest

    if isinstance(manifest, Manifest):
        _manifest = manifest
    else:
        _manifest = load_manifest(manifest)

    return sorted(_instrument_module(module, _manifest, recurse=recurse))


def _instrument_module(
    module: types.ModuleType,
    manifest: Manifest,
    *,
    recurse: bool,
) -> list[str]:
    """Walk *module* and monkey-patch functions that match a manifest rule."""
    wrapped: list[str] = []
    mod_name = module.__name__

    for attr_name, obj in inspect.getmembers(module, inspect.isfunction):
        if attr_name.startswith("_"):
            continue
        # Skip functions that were imported into this module from elsewhere.
        if obj.__module__ != mod_name:
            continue
        rule = manifest.match(attr_name)
        if rule is None:
            continue
        setattr(module, attr_name, _wrap_with_rule(obj, attr_name, rule))
        wrapped.append(f"{mod_name}.{attr_name}")

    if recurse and hasattr(module, "__path__"):
        for _, submod_name, _ in pkgutil.walk_packages(
            module.__path__, prefix=mod_name + "."
        ):
            submod = sys.modules.get(submod_name)
            if submod is None:
                submod = importlib.import_module(submod_name)
            wrapped.extend(_instrument_module(submod, manifest, recurse=False))

    return wrapped


def _wrap_with_rule(func: F, name: str, rule: ManifestRule) -> F:
    """Apply :func:`enforce` to *func* using settings from *rule*."""
    return enforce(
        tool_name=name,
        policy_id=rule.policy_id,
        context=rule.context if rule.context else None,
        evidence=rule.evidence,
    )(func)


def tool(
    func: F | None = None,
    *,
    tool_name: str | None = None,
    policy_id: str | None = None,
    context: dict[str, Any] | None = None,
    # Phase 2 — GDPR Article 30 processing-register matching.
    data_categories: list[str] | None = None,
    purpose: str | None = None,
    processing_register_ref: str | None = None,
    # Phase 6 — dataset lineage.
    dataset_ref: str | None = None,
) -> F | Callable[[F], F]:
    """Decorator to enforce Vault clearance on a single function.

    Use this as an escape hatch for functions that live outside the modules
    passed to :func:`auto_instrument`.  If a manifest has been loaded its
    rules are applied first; explicit keyword arguments always take precedence.

    Works with or without call parentheses::

        @bylaw.tool
        def my_fn(amount: float):
            token = bylaw.current_token()
            ...

        @bylaw.tool(policy_id="financial-high-risk")
        def stripe_charge(amount: float, customer_id: str):
            token = bylaw.current_token()
            ...

    Args:
        func: The function to wrap (populated automatically when the decorator
            is used without parentheses).
        tool_name: Override the tool name used in the clearance request
            (defaults to ``func.__name__``).
        policy_id: Policy ID override (manifest match used when omitted).
        context: Extra key/value pairs forwarded to the clearance request.
        data_categories: Personal-data categories this action will touch
            (Phase 2 register matching).
        purpose: Purpose of processing (Phase 2 register matching).
        processing_register_ref: Optional UUID hint of the matching register.
        dataset_ref: Logical dataset ref this action reads/writes (Phase 6).
    """
    def decorator(f: F) -> F:
        resolved_name = tool_name or f.__name__
        resolved_policy = policy_id
        resolved_context: dict[str, Any] = dict(context or {})
        resolved_evidence: EvidenceRule | None = None

        # Apply manifest rule if available, explicit kwargs take precedence.
        if _manifest is not None:
            rule = _manifest.match(resolved_name)
            if rule is not None:
                if resolved_policy is None:
                    resolved_policy = rule.policy_id
                resolved_context = {**rule.context, **resolved_context}
                resolved_evidence = rule.evidence

        return enforce(
            tool_name=resolved_name,
            policy_id=resolved_policy,
            context=resolved_context or None,
            evidence=resolved_evidence,
            data_categories=data_categories,
            purpose=purpose,
            processing_register_ref=processing_register_ref,
            dataset_ref=dataset_ref,
        )(f)

    if func is not None:
        # @bylaw.tool  — called without parentheses
        return decorator(func)
    # @bylaw.tool(...)  — called with arguments
    return decorator


# ---------------------------------------------------------------------------
# New low-code decorator: enforce()
# ---------------------------------------------------------------------------

def enforce(
    *,
    tool_name: str | None = None,
    policy_id: str | None = None,
    context: dict[str, Any] | None = None,
    on_review_pending: Callable[[PendingApproval], None] | None = None,
    evidence: EvidenceRule | None = None,
    # Phase 2 — GDPR Article 30 processing-register matching.
    data_categories: list[str] | None = None,
    purpose: str | None = None,
    processing_register_ref: str | None = None,
    # Phase 6 — dataset lineage.
    dataset_ref: str | None = None,
) -> Callable[[F], F]:
    """Decorator that enforces Vault clearance before a function executes.

    Requires :func:`configure` to have been called at startup.  The A-JWT
    token is stored in a context variable and can be retrieved inside the
    decorated function via :func:`current_token`::

        import bylaw_python as bylaw

        bylaw.configure(agent_id="finance-agent")

        @bylaw.enforce(tool_name="stripe_refund")
        def process_refund(amount: float, reason: str):
            token = bylaw.current_token()
            stripe.refund(amount=amount, metadata={"vault_token": token})

    Works with both sync and async functions.  Unlike :func:`vault_enforce`,
    no ``_clearance`` kwarg is injected — the function signature is untouched.

    Args:
        on_review_pending: Optional callback invoked when ``review_mode="detach"``
            and the Vault returns a ``pending_review`` response.  Receives a
            :class:`~bylaw_python.PendingApproval` handle.  After the callback
            returns, :class:`~bylaw_python.ReviewPendingError` is re-raised so
            the calling framework can abort the current turn.
    """

    def decorator(func: F) -> F:
        resolved_name = tool_name or func.__name__
        # Clearance runs for plain enforce()/clearance rules. An evidence-only
        # rule (no policy_id) skips clearance and only runs the evidence layer.
        do_clearance = evidence is None or policy_id is not None
        ev_action = evidence is not None and evidence.kind == "action"
        ev_source = evidence is not None and evidence.kind == "source"

        def _build_request(client: BylawClient, tool_args: dict[str, Any]) -> ClearanceRequest:
            return ClearanceRequest(
                tool_name=resolved_name,
                tool_args=tool_args,
                agent_id=client.config.agent_id,
                session_id=client.config.session_id,
                context={**(context or {}), **({"policy_id": policy_id} if policy_id else {})},
                data_categories=data_categories,
                purpose=purpose,
                processing_register_ref=processing_register_ref,
                dataset_ref=dataset_ref,
            )

        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                client = _get_default_client()
                tool_args = _extract_tool_args(func, args, kwargs)
                evidence_on = client.config.evidence_mode != "off"

                clearance: ClearanceResponse | None = None
                if do_clearance:
                    try:
                        clearance = await client.arequest_clearance(_build_request(client, tool_args))
                    except ReviewPendingError as exc:
                        if on_review_pending is not None:
                            on_review_pending(exc.pending_approval)
                        raise

                if ev_action and evidence_on:
                    await aguard_action(client, evidence, tool_args)

                token = _current_clearance.set(clearance) if clearance is not None else None
                try:
                    result = await func(*args, **kwargs)
                finally:
                    if token is not None:
                        _current_clearance.reset(token)

                if ev_source and evidence_on:
                    try:
                        await aobserve_source(client, evidence, tool_args, result)
                    except Exception:  # observation must never break the agent
                        _evidence_log.warning("evidence: source observation failed", exc_info=True)
                return result

            return async_wrapper  # type: ignore[return-value]

        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                client = _get_default_client()
                tool_args = _extract_tool_args(func, args, kwargs)
                evidence_on = client.config.evidence_mode != "off"

                clearance: ClearanceResponse | None = None
                if do_clearance:
                    try:
                        clearance = client.request_clearance(_build_request(client, tool_args))
                    except ReviewPendingError as exc:
                        if on_review_pending is not None:
                            on_review_pending(exc.pending_approval)
                        raise

                if ev_action and evidence_on:
                    guard_action(client, evidence, tool_args)

                token = _current_clearance.set(clearance) if clearance is not None else None
                try:
                    result = func(*args, **kwargs)
                finally:
                    if token is not None:
                        _current_clearance.reset(token)

                if ev_source and evidence_on:
                    try:
                        observe_source(client, evidence, tool_args, result)
                    except Exception:  # observation must never break the agent
                        _evidence_log.warning("evidence: source observation failed", exc_info=True)
                return result

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
        client: BylawClient,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        *,
        context: dict[str, Any] | None = None,
        policy_id: str | None = None,
        data_categories: list[str] | None = None,
        purpose: str | None = None,
        processing_register_ref: str | None = None,
        dataset_ref: str | None = None,
    ) -> None:
        self.client = client
        self.tool_name = tool_name
        self.tool_args = tool_args or {}
        self.context = context or {}
        self.policy_id = policy_id
        self.data_categories = data_categories
        self.purpose = purpose
        self.processing_register_ref = processing_register_ref
        self.dataset_ref = dataset_ref
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
            data_categories=self.data_categories,
            purpose=self.purpose,
            processing_register_ref=self.processing_register_ref,
            dataset_ref=self.dataset_ref,
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
    client: BylawClient,
    *,
    tool_name: str | None = None,
    policy_id: str | None = None,
    context: dict[str, Any] | None = None,
    data_categories: list[str] | None = None,
    purpose: str | None = None,
    processing_register_ref: str | None = None,
    dataset_ref: str | None = None,
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
                    data_categories=data_categories,
                    purpose=purpose,
                    processing_register_ref=processing_register_ref,
                    dataset_ref=dataset_ref,
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
                    data_categories=data_categories,
                    purpose=purpose,
                    processing_register_ref=processing_register_ref,
                    dataset_ref=dataset_ref,
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
