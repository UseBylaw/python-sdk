# Bylaw ALCV — Adapter Core Helpers
# Shared scaffolding used by the LangChain, LlamaIndex, and CrewAI adapters.
# Framework-specific glue (callback handlers, sync vs async, error-translation
# policy) stays per-adapter — only the genuinely identical pieces live here.

from __future__ import annotations

from typing import Any

from ..client import BylawClient
from ..enforce import _get_default_client
from ..models import ClearanceRequest


def resolve_client(client: BylawClient | None) -> BylawClient:
    """Return the explicit client or fall back to the module-level default
    configured via :func:`bylaw_python.configure`.
    """
    if client is not None:
        return client
    return _get_default_client()


def build_clearance_request(
    *,
    tool_name: str,
    tool_args: dict[str, Any],
    client: BylawClient,
    policy_id: str | None = None,
    extra_context: dict[str, Any] | None = None,
    data_categories: list[str] | None = None,
    purpose: str | None = None,
    processing_register_ref: str | None = None,
    dataset_ref: str | None = None,
) -> ClearanceRequest:
    """Build a ClearanceRequest with adapter-agnostic defaults pulled from
    ``client.config``. ``policy_id``, when set, is merged into ``context``
    after ``extra_context`` so it always wins for that key.

    Phase 2/6 fields (``data_categories``, ``purpose``,
    ``processing_register_ref``, ``dataset_ref``) are forwarded as top-level
    fields so the Vault's processing-register / dataset-lineage validators
    can match them.
    """
    ctx: dict[str, Any] = dict(extra_context or {})
    if policy_id:
        ctx["policy_id"] = policy_id
    return ClearanceRequest(
        tool_name=tool_name,
        tool_args=tool_args,
        agent_id=client.config.agent_id,
        session_id=client.config.session_id,
        context=ctx,
        data_categories=data_categories,
        purpose=purpose,
        processing_register_ref=processing_register_ref,
        dataset_ref=dataset_ref,
    )
