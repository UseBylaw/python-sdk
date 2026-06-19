# Bylaw ALCV — Client-side counterparty hints
#
# Mirrors vault/internal/counterparty: best-effort extraction of the
# destination provider/URI/account from a tool name + tool_args dict.
# The Vault re-runs its own extractor chain, so this is a hint to
# pre-populate the wire fields when the SDK has unambiguous signal.
#
# Caller-supplied destination_* always wins on both sides of the wire.

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse


_PROVIDER_HOST_PREFIXES = ("www.", "api.", "api-")


def _provider_from_host(host: str) -> str:
    """Strip common gateway prefixes so regional subdomains group together.
    Does not attempt eTLD+1 parsing — provider taxonomy is curated upstream."""
    host = host.lower().split(":", 1)[0]
    for prefix in _PROVIDER_HOST_PREFIXES:
        if host.startswith(prefix):
            return host[len(prefix):]
    return host


def _string_arg(tool_args: dict[str, Any], key: str) -> str:
    value = tool_args.get(key)
    return value if isinstance(value, str) else ""


def _stripe(tool_name: str, tool_args: dict[str, Any]) -> dict[str, str] | None:
    if "stripe" not in tool_name:
        return None
    out: dict[str, str] = {
        "destination_uri": "https://api.stripe.com",
        "destination_provider": "stripe",
    }
    api_key = _string_arg(tool_args, "api_key")
    if api_key.startswith("sk_") and len(api_key) >= 12:
        out["destination_account_ref"] = api_key[:12]
    elif api_key.startswith("sk_"):
        out["destination_account_ref"] = api_key
    account = _string_arg(tool_args, "account")
    if account:
        out["destination_account_ref"] = account
    return out


def _twilio(tool_name: str, tool_args: dict[str, Any]) -> dict[str, str] | None:
    if "twilio" not in tool_name:
        return None
    out: dict[str, str] = {
        "destination_uri": "https://api.twilio.com",
        "destination_provider": "twilio",
    }
    sid = _string_arg(tool_args, "account_sid")
    if sid:
        out["destination_account_ref"] = sid
    return out


def _slack(tool_name: str, tool_args: dict[str, Any]) -> dict[str, str] | None:
    if "slack" not in tool_name:
        return None
    out: dict[str, str] = {
        "destination_uri": "https://slack.com/api",
        "destination_provider": "slack",
    }
    team = _string_arg(tool_args, "team_id") or _string_arg(tool_args, "workspace")
    if team:
        out["destination_account_ref"] = team
    return out


def _bedrock(tool_name: str, tool_args: dict[str, Any]) -> dict[str, str] | None:
    if "bedrock" not in tool_name:
        return None
    out: dict[str, str] = {
        "destination_uri": "https://bedrock-runtime.amazonaws.com",
        "destination_provider": "aws-bedrock",
    }
    model_id = _string_arg(tool_args, "model_id") or _string_arg(tool_args, "model")
    if model_id:
        out["destination_account_ref"] = model_id
    return out


def _openai(tool_name: str, tool_args: dict[str, Any]) -> dict[str, str] | None:
    if "openai" not in tool_name and "gpt" not in tool_name:
        return None
    out: dict[str, str] = {
        "destination_uri": "https://api.openai.com",
        "destination_provider": "openai",
    }
    org = _string_arg(tool_args, "organization") or _string_arg(tool_args, "org_id")
    if org:
        out["destination_account_ref"] = org
    return out


def _anthropic(tool_name: str, tool_args: dict[str, Any]) -> dict[str, str] | None:
    if "anthropic" not in tool_name and "claude" not in tool_name:
        return None
    out: dict[str, str] = {
        "destination_uri": "https://api.anthropic.com",
        "destination_provider": "anthropic",
    }
    org = _string_arg(tool_args, "organization")
    if org:
        out["destination_account_ref"] = org
    return out


def _generic_http(tool_name: str, tool_args: dict[str, Any]) -> dict[str, str] | None:
    for key in ("url", "endpoint", "uri", "host"):
        raw = _string_arg(tool_args, key)
        if not raw:
            continue
        parsed = urlparse(raw)
        if not parsed.netloc:
            continue
        return {
            "destination_uri": raw,
            "destination_provider": _provider_from_host(parsed.netloc),
        }
    return None


_EXTRACTORS = (_stripe, _twilio, _slack, _bedrock, _openai, _anthropic, _generic_http)


def extract(tool_name: str, tool_args: dict[str, Any] | None) -> dict[str, str]:
    """Return any inferred destination_* fields. Empty dict on no match."""
    if not tool_name:
        return {}
    name_lower = tool_name.lower()
    args = tool_args or {}
    for ex in _EXTRACTORS:
        result = ex(name_lower, args)
        if result:
            return result
    return {}
