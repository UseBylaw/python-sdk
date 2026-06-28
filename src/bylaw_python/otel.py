from __future__ import annotations

from importlib import import_module
from typing import Any, cast

from .models import ClearanceRequest, ClearanceResponse

_UNSET = object()
_otel_override: Any = _UNSET


def _load_otel() -> tuple[Any, Any] | None:
    if _otel_override is not _UNSET:
        return cast("tuple[Any, Any] | None", _otel_override)
    try:
        trace = import_module("opentelemetry.trace")
        propagate = import_module("opentelemetry.propagate")
    except Exception:
        return None
    return trace, propagate


def _format_trace_id(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, int):
        return f"{value:032x}"
    return ""


def _format_span_id(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, int):
        return f"{value:016x}"
    return ""


def _active_span(trace: Any) -> Any | None:
    try:
        span = trace.get_current_span()
        ctx = span.get_span_context()
        if not getattr(ctx, "is_valid", False):
            return None
        return span
    except Exception:
        return None


def current_otel_metadata(enabled: bool) -> dict[str, Any] | None:
    if not enabled:
        return None
    api = _load_otel()
    if api is None:
        return None
    trace, _ = api
    span = _active_span(trace)
    if span is None:
        return None
    try:
        ctx = span.get_span_context()
        out: dict[str, Any] = {
            "trace_id": _format_trace_id(ctx.trace_id),
            "span_id": _format_span_id(ctx.span_id),
            "trace_flags": int(ctx.trace_flags),
        }
        trace_state = getattr(ctx, "trace_state", None)
        if trace_state:
            state = trace_state.to_header() if hasattr(trace_state, "to_header") else str(trace_state)
            if state:
                out["trace_state"] = state
        return out
    except Exception:
        return None


def inject_otel_headers(headers: dict[str, str], enabled: bool) -> dict[str, str]:
    if not enabled:
        return headers
    api = _load_otel()
    if api is None:
        return headers
    trace, propagate = api
    if _active_span(trace) is None:
        return headers
    carrier = dict(headers)
    try:
        propagate.inject(carrier)
    except Exception:
        return headers
    return carrier


def _attr(value: Any) -> str | int | float | bool | None:
    if isinstance(value, (str, int, float, bool)):
        return value
    return None


def record_clearance_event(
    enabled: bool,
    name: str,
    request: ClearanceRequest,
    clearance: ClearanceResponse,
) -> None:
    if not enabled:
        return
    api = _load_otel()
    if api is None:
        return
    trace, _ = api
    span = _active_span(trace)
    if span is None:
        return
    attrs: dict[str, str | int | float | bool] = {}

    def put(key: str, value: Any) -> None:
        v = _attr(value)
        if v is not None and v != "":
            attrs[key] = v

    try:
        put("bylaw.request_id", clearance.request_id)
        put("bylaw.decision_status", clearance.decision_status)
        put("bylaw.status", clearance.status)
        put("bylaw.reason_code", clearance.reason_code)
        put("bylaw.reason", clearance.reason)
        put("bylaw.policy_version_id", clearance.policy_version_id)
        put("bylaw.policy_content_hash", clearance.policy_content_hash)
        put("bylaw.confidence_bucket", clearance.confidence_bucket)
        put("bylaw.minimum_confidence_bucket", clearance.minimum_confidence_bucket)
        put("bylaw.tool_name", request.tool_name)
        put("bylaw.agent_id", request.agent_id)
        put("bylaw.session_id", request.session_id)
        put("bylaw.requires_manual_review", clearance.requires_manual_review)
        put("bylaw.latency_ms", getattr(clearance, "latency_ms", None))
        span.add_event(name, attrs)
    except Exception:
        return


def _set_otel_api_for_tests(api: tuple[Any, Any] | None | object = _UNSET) -> None:
    global _otel_override
    _otel_override = api
