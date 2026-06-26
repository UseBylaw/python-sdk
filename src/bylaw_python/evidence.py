# Bylaw ALCV — Evidence weaving (Phase 2)
#
# Source observation and protected-action guarding, layered transparently on top
# of the existing enforce() wrappers. The agent's reasoning loop is untouched:
# source tool results are extracted into Vault facts, fact IDs are kept in a
# session store the agent never sees, and protected actions are checked against
# current evidence before they run.

from __future__ import annotations

import contextlib
import contextvars
import inspect
import logging
from typing import Any, Callable, Iterator

from .client import BylawClient
from .exceptions import EvidenceBlockedError, EvidenceError, VaultConnectionError
from .jsonpath import extract_path
from .manifest import EvidenceRule
from .models import (
    Challenge,
    ChallengeResolution,
    CheckActionRequest,
    CheckActionResult,
    FactRef,
    RegisterFactRequest,
    ResolveChallengeRequest,
)
from .session_store import InMemorySessionStore, SessionEvidenceStore

logger = logging.getLogger("bylaw.evidence")

# A challenge handler renders the challenge in the HOST's UI and returns the
# chosen resolution. It may be sync or async.
ChallengeHandler = Callable[[Challenge], Any]

_session_ctx: contextvars.ContextVar[tuple[str, str] | None] = contextvars.ContextVar(
    "_bylaw_evidence_session", default=None
)
_store: SessionEvidenceStore | None = None
_store_backend: str | None = None
_challenge_handler: ChallengeHandler | None = None


def set_challenge_handler(handler: ChallengeHandler | None) -> None:
    """Register the host challenge handler (Phase 3).

    In enforce mode, when a protected action needs human judgment the SDK calls
    this handler with the :class:`Challenge`; the host renders it in its own UI
    and returns a :class:`ChallengeResolution` (or a dict / 3-tuple). The SDK
    then resolves the challenge and resumes (allow) or blocks (deny).
    """
    global _challenge_handler
    _challenge_handler = handler


def _coerce_resolution(value: Any) -> ChallengeResolution:
    if isinstance(value, ChallengeResolution):
        return value
    if isinstance(value, dict):
        return ChallengeResolution(**value)
    if isinstance(value, (tuple, list)):
        return ChallengeResolution(
            selected_resolution=value[0],
            resolved_by=value[1] if len(value) > 1 else "host",
            resolver_role=value[2] if len(value) > 2 else "",
        )
    raise EvidenceError("challenge handler must return a ChallengeResolution, dict, or tuple")


def _resolve_request(challenge: Challenge, resolution: ChallengeResolution) -> ResolveChallengeRequest:
    return ResolveChallengeRequest(
        challenge_id=challenge.challenge_id,
        challenge_token=challenge.challenge_token,
        selected_resolution=resolution.selected_resolution,
        resolved_by=resolution.resolved_by,
        resolver_role=resolution.resolver_role,
        field=challenge.field,
    )


def _normalize_backend(backend: str | None) -> str:
    return (backend or "memory").strip().lower().replace("_", "-")


def _configure_session_store(backend: str | None) -> None:
    """Validate and initialize the configured session evidence store backend."""
    global _store, _store_backend
    backend_name = _normalize_backend(backend)
    if backend_name not in {"memory", "in-memory"}:
        _get_store(backend)
        return
    if _store_backend == "manual" and _store is not None:
        return
    _store = InMemorySessionStore()
    _store_backend = backend_name


def _get_store(backend: str | None = "memory") -> SessionEvidenceStore:
    global _store, _store_backend
    backend_name = _normalize_backend(backend)
    if backend_name not in {"memory", "in-memory"}:
        if _store_backend == "manual" and _store is not None:
            return _store
        raise ValueError(
            "Unsupported evidence_session_backend "
            f"{backend!r}; configure a custom store with set_session_store()"
        )
    if _store is None:
        _store = InMemorySessionStore()
        _store_backend = backend_name
    return _store


def set_session_store(store: SessionEvidenceStore | None) -> None:
    """Override the process session evidence store (tests / Redis backend)."""
    global _store, _store_backend
    _store = store
    _store_backend = "manual" if store is not None else None


@contextlib.contextmanager
def evidence_session(session_id: str, customer_id: str = "") -> Iterator[None]:
    """Scope a logical conversation's evidence to a ``(session, customer)`` pair.

    Wrap the turn so auto-registered facts and protected actions are attributed
    correctly even when one process serves many customers/sessions::

        with bylaw.evidence_session(session_id="s1", customer_id="cust_42"):
            profile = get_customer_profile(customer_id="cust_42")
            rec = generate_recommendation(customer_id="cust_42")
    """
    token = _session_ctx.set((session_id, customer_id))
    try:
        yield
    finally:
        _session_ctx.reset(token)


def _active_session(client: BylawClient) -> tuple[str, str]:
    ctx = _session_ctx.get()
    if ctx is not None:
        return ctx
    return (client.config.session_id, "")


def _resolve_customer(
    rule: EvidenceRule, tool_args: dict[str, Any], result: Any, default_customer: str
) -> str:
    if rule.customer_id:
        val = extract_path({"args": tool_args, "result": result}, rule.customer_id)
        if val is not None:
            return str(val)
    return default_customer


def _fact_request(
    rule: EvidenceRule, session_id: str, customer_id: str, agent_id: str, field: str, value: Any
) -> RegisterFactRequest:
    return RegisterFactRequest(
        customer_id=customer_id,
        session_id=session_id,
        field=field,
        value=value,
        source_type=rule.source_type or "tool_call",
        source_id=agent_id,
    )


def _build_action_request(
    client: BylawClient, rule: EvidenceRule, tool_args: dict[str, Any]
) -> tuple[CheckActionRequest, str, str] | None:
    session_id, ctx_customer = _active_session(client)
    customer_id = _resolve_customer(rule, tool_args, None, ctx_customer)
    if not customer_id:
        if client.config.evidence_mode == "enforce":
            logger.warning("evidence: no customer id for action tool; blocking action")
            raise EvidenceBlockedError("missing customer id for action evidence check")
        logger.warning("evidence: no customer id for action tool; skipping action guard")
        return None
    store = _get_store(client.config.evidence_session_backend)
    fields = list(rule.requires) or None
    fact_ids = store.fact_ids(session_id, customer_id, fields)
    obligations = sorted(store.obligations(session_id, customer_id))
    req = CheckActionRequest(
        customer_id=customer_id,
        session_id=session_id,
        mode=client.config.evidence_mode,
        action_type=rule.action_type or "",
        facts=[FactRef(fact_id=fid) for fid in fact_ids],
        obligations=obligations,
    )
    return req, session_id, customer_id


def _record_obligations(session_id: str, customer_id: str, result: CheckActionResult) -> None:
    if result.obligations:
        _get_store().add_obligations(session_id, customer_id, [o.code for o in result.obligations])


def _block(result: CheckActionResult) -> None:
    raise EvidenceBlockedError(result.reason, result.decision, result.receipt_id)


# ---------------------------------------------------------------------------
# Sync entry points
# ---------------------------------------------------------------------------

def guard_action(client: BylawClient, rule: EvidenceRule, tool_args: dict[str, Any]) -> None:
    built = _build_action_request(client, rule, tool_args)
    if built is None:
        return
    req, session_id, customer_id = built
    try:
        result = client.check_action(req)
    except (EvidenceError, VaultConnectionError) as exc:
        if client.config.evidence_mode == "enforce":
            raise
        logger.warning("evidence: check-action failed (observe, continuing): %s", exc)
        return
    _record_obligations(session_id, customer_id, result)
    if result.is_allowed:
        return
    if client.config.evidence_mode != "enforce":
        logger.info("evidence[observe]: would_%s %s — %s", result.decision, result.action_type, result.reason)
        return
    # Enforce: a review pauses for host-native resolution, then resumes (R3.9).
    if result.decision == "review" and result.challenge is not None and _challenge_handler is not None:
        resolution = _coerce_resolution(_challenge_handler(result.challenge))
        final = client.resolve_challenge(_resolve_request(result.challenge, resolution))
        _record_obligations(session_id, customer_id, final)
        if final.is_allowed:
            return
        _block(final)
    _block(result)


def observe_source(
    client: BylawClient, rule: EvidenceRule, tool_args: dict[str, Any], result: Any
) -> None:
    session_id, ctx_customer = _active_session(client)
    customer_id = _resolve_customer(rule, tool_args, result, ctx_customer)
    if not customer_id:
        logger.warning("evidence: no customer id for source tool; skipping fact registration")
        return
    store = _get_store(client.config.evidence_session_backend)
    root = {"args": tool_args, "result": result}
    for field, path in rule.fields.items():
        value = extract_path(root, path)
        if value is None:
            continue
        try:
            fact = client.register_fact(
                _fact_request(rule, session_id, customer_id, client.config.agent_id, field, value)
            )
        except EvidenceError as exc:
            logger.warning("evidence: fact registration failed for %s: %s", field, exc)
            continue
        if fact.id:
            store.put_fact(session_id, customer_id, field, fact.id)


# ---------------------------------------------------------------------------
# Async entry points
# ---------------------------------------------------------------------------

async def aguard_action(client: BylawClient, rule: EvidenceRule, tool_args: dict[str, Any]) -> None:
    built = _build_action_request(client, rule, tool_args)
    if built is None:
        return
    req, session_id, customer_id = built
    try:
        result = await client.acheck_action(req)
    except (EvidenceError, VaultConnectionError) as exc:
        if client.config.evidence_mode == "enforce":
            raise
        logger.warning("evidence: check-action failed (observe, continuing): %s", exc)
        return
    _record_obligations(session_id, customer_id, result)
    if result.is_allowed:
        return
    if client.config.evidence_mode != "enforce":
        logger.info("evidence[observe]: would_%s %s — %s", result.decision, result.action_type, result.reason)
        return
    if result.decision == "review" and result.challenge is not None and _challenge_handler is not None:
        resolution = _challenge_handler(result.challenge)
        if inspect.isawaitable(resolution):
            resolution = await resolution
        final = await client.aresolve_challenge(_resolve_request(result.challenge, _coerce_resolution(resolution)))
        _record_obligations(session_id, customer_id, final)
        if final.is_allowed:
            return
        _block(final)
    _block(result)


async def aobserve_source(
    client: BylawClient, rule: EvidenceRule, tool_args: dict[str, Any], result: Any
) -> None:
    session_id, ctx_customer = _active_session(client)
    customer_id = _resolve_customer(rule, tool_args, result, ctx_customer)
    if not customer_id:
        logger.warning("evidence: no customer id for source tool; skipping fact registration")
        return
    store = _get_store(client.config.evidence_session_backend)
    root = {"args": tool_args, "result": result}
    for field, path in rule.fields.items():
        value = extract_path(root, path)
        if value is None:
            continue
        try:
            fact = await client.aregister_fact(
                _fact_request(rule, session_id, customer_id, client.config.agent_id, field, value)
            )
        except EvidenceError as exc:
            logger.warning("evidence: fact registration failed for %s: %s", field, exc)
            continue
        if fact.id:
            store.put_fact(session_id, customer_id, field, fact.id)
