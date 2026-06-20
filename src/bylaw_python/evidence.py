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
    CheckOutputRequest,
    FactRef,
    OutputClaim,
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


def _coerce_output_claims(raw: Any) -> list[OutputClaim]:
    if not isinstance(raw, list):
        return []
    out: list[OutputClaim] = []
    for item in raw:
        if isinstance(item, OutputClaim):
            out.append(item)
        elif isinstance(item, dict):
            out.append(OutputClaim(**item))
    return out


def _build_output_request(
    client: BylawClient,
    rule: EvidenceRule | None,
    response_text: str,
    tool_args: dict[str, Any],
    result: Any,
    customer_override: str = "",
) -> tuple[CheckOutputRequest, str, str] | None:
    """Build a check-output request from a wrapped result or raw text.

    Attaches ALL of the customer's session facts (not a ``requires`` subset) so
    Vault's derivation search has every numeric input available to ground a
    number. Returns ``None`` when no customer can be resolved.
    """
    session_id, ctx_customer = _active_session(client)
    customer_id = customer_override
    if not customer_id and rule is not None:
        customer_id = _resolve_customer(rule, tool_args, result, ctx_customer)
    if not customer_id:
        customer_id = ctx_customer
    if not customer_id:
        return None
    store = _get_store()
    fact_ids = store.fact_ids(session_id, customer_id, None)
    claims: list[OutputClaim] = []
    if rule is not None and rule.claims_path:
        claims = _coerce_output_claims(
            extract_path({"args": tool_args, "result": result}, rule.claims_path)
        )
    req = CheckOutputRequest(
        customer_id=customer_id,
        session_id=session_id,
        mode=client.config.evidence_output_mode,
        action_type=(rule.action_type or "") if rule is not None else "",
        response_text=response_text,
        facts=[FactRef(fact_id=fid) for fid in fact_ids],
        output_claims=claims,
    )
    return req, session_id, customer_id


def _extract_response_text(rule: EvidenceRule, tool_args: dict[str, Any], result: Any) -> str:
    """Resolve the response text from a wrapped tool's result per the rule. With
    no ``response_text`` path, the whole result is stringified."""
    if rule.response_text:
        val = extract_path({"args": tool_args, "result": result}, rule.response_text)
        return "" if val is None else str(val)
    return "" if result is None else str(result)


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


def guard_output(
    client: BylawClient,
    response_text: str,
    *,
    customer_id: str = "",
    rule: EvidenceRule | None = None,
    tool_args: dict[str, Any] | None = None,
    result: Any = None,
) -> CheckActionResult | None:
    """Verify that the numbers in ``response_text`` are grounded (sync, Phase 4).

    Reads ``client.config.evidence_output_mode`` (NOT ``evidence_mode``): output
    enforcement is opt-in because a false positive blocks a legitimate answer.
    ``observe`` records ``would_*`` and never raises; ``enforce`` raises
    :class:`EvidenceBlockedError` on an ungrounded number, pausing on a review
    for host-native resolution first. Returns the result (or ``None`` if skipped).
    """
    mode = client.config.evidence_output_mode
    if mode == "off":
        return None
    if not response_text:
        if mode == "enforce":
            raise EvidenceError("evidence output enforcement requires non-empty response text")
        return None
    built = _build_output_request(client, rule, response_text, tool_args or {}, result, customer_id)
    if built is None:
        if mode == "enforce":
            raise EvidenceError("evidence output enforcement requires customer id")
        logger.warning("evidence: no customer id for output guard; skipping")
        return None
    req, session_id, resolved_customer = built
    try:
        result_check = client.check_output(req)
    except EvidenceError as exc:
        if mode == "enforce":
            raise
        logger.warning("evidence: check-output failed (observe, continuing): %s", exc)
        return None
    _record_obligations(session_id, resolved_customer, result_check)
    if result_check.is_allowed:
        return result_check
    if mode != "enforce":
        logger.info("evidence[observe]: would_%s output — %s", result_check.decision, result_check.reason)
        return result_check
    if result_check.decision == "review" and result_check.challenge is not None and _challenge_handler is not None:
        resolution = _coerce_resolution(_challenge_handler(result_check.challenge))
        final = client.resolve_challenge(_resolve_request(result_check.challenge, resolution))
        _record_obligations(session_id, resolved_customer, final)
        if final.is_allowed:
            return final
        _block(final)
    _block(result_check)


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


async def aguard_output(
    client: BylawClient,
    response_text: str,
    *,
    customer_id: str = "",
    rule: EvidenceRule | None = None,
    tool_args: dict[str, Any] | None = None,
    result: Any = None,
) -> CheckActionResult | None:
    """Async :func:`guard_output`."""
    mode = client.config.evidence_output_mode
    if mode == "off":
        return None
    if not response_text:
        if mode == "enforce":
            raise EvidenceError("evidence output enforcement requires non-empty response text")
        return None
    built = _build_output_request(client, rule, response_text, tool_args or {}, result, customer_id)
    if built is None:
        if mode == "enforce":
            raise EvidenceError("evidence output enforcement requires customer id")
        logger.warning("evidence: no customer id for output guard; skipping")
        return None
    req, session_id, resolved_customer = built
    try:
        result_check = await client.acheck_output(req)
    except EvidenceError as exc:
        if mode == "enforce":
            raise
        logger.warning("evidence: check-output failed (observe, continuing): %s", exc)
        return None
    _record_obligations(session_id, resolved_customer, result_check)
    if result_check.is_allowed:
        return result_check
    if mode != "enforce":
        logger.info("evidence[observe]: would_%s output — %s", result_check.decision, result_check.reason)
        return result_check
    if result_check.decision == "review" and result_check.challenge is not None and _challenge_handler is not None:
        resolution = _challenge_handler(result_check.challenge)
        if inspect.isawaitable(resolution):
            resolution = await resolution
        final = await client.aresolve_challenge(
            _resolve_request(result_check.challenge, _coerce_resolution(resolution))
        )
        _record_obligations(session_id, resolved_customer, final)
        if final.is_allowed:
            return final
        _block(final)
    _block(result_check)


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
