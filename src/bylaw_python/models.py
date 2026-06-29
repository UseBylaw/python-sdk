# Bylaw ALCV — Data Models
# Pydantic models for Vault API request/response payloads

from __future__ import annotations

from typing import Any, Literal, cast

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)

_MISSING = object()


class ClearanceRequest(BaseModel):
    """Payload sent to the Vault's ``/request-clearance`` endpoint."""

    tool_name: str = Field(..., description="Name of the tool the agent wants to invoke")
    tool_args: dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments the agent will pass to the tool",
    )
    agent_id: str = Field(default="default-agent", description="Identifier for the calling agent")
    session_id: str = Field(default="", description="Session grouping identifier")
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context for the Vault's policy judge (e.g. conversation history)",
    )
    human_principal: str | None = Field(
        default=None,
        description="Advisory OIDC sub of the human on whose behalf the agent acts",
    )
    parent_jti: str | None = Field(
        default=None,
        description="JTI of the parent A-JWT; present on delegated sub-agent requests",
    )
    destination_uri: str | None = Field(
        default=None,
        description="Canonical URI the action will be sent to (e.g. https://api.openai.com/v1/chat/completions)",
    )
    destination_provider: str | None = Field(
        default=None,
        description="Canonical provider key (e.g. openai, stripe, anthropic, aws-bedrock)",
    )
    destination_account_ref: str | None = Field(
        default=None,
        description="Account/org/workspace ref within the provider (e.g. Stripe acct id, Slack team id)",
    )
    # Phase 2 — GDPR Article 30 processing-register matching.
    # When supplied, the Vault's pre-LLM validator chain checks for an active
    # processing register that covers (data_categories ⊇ requested,
    # purpose ∈ register.purposes, recipient ∈ register.recipients). Unmatched
    # requests are denied with reason_code='processing_no_register_match'.
    #
    # WIRE NOTE: Vault decodes the clearance body into a typed Go struct whose
    # GDPR fields live nested under ``context`` (RequestContext): keys
    # ``purpose``, ``data_categories``, ``dataset_ref``. These attributes are
    # therefore ``exclude=True`` (kept on the public API) and folded into the
    # serialized ``context`` object by ``_serialize_with_nested_gdpr`` below.
    # ``processing_register_ref`` has NO field anywhere on Vault's clearance
    # wire (typed struct lacks it), so it is a LOCAL-ONLY attribute and is never
    # emitted. A ``mode='before'`` validator lifts the three wired fields back
    # out of an incoming ``context`` so attribute round-trips still hold.
    data_categories: list[str] | None = Field(
        default=None,
        exclude=True,
        description="Personal-data categories this action will touch (e.g. ['customer_email','transaction_amount'])",
    )
    purpose: str | None = Field(
        default=None,
        exclude=True,
        description="Purpose of processing (e.g. 'fraud_detection', 'billing'); must be in matched register's purposes",
    )
    processing_register_ref: str | None = Field(
        default=None,
        exclude=True,
        description="Optional UUID hint of which register this action anchors to; Vault still does authoritative match",
    )
    # Phase 6 — dataset lineage. When supplied, dataset sheets auto-derive
    # row counts, schema fingerprints, and consent-basis breakdowns from
    # ledger replay scoped to events with this ref.
    dataset_ref: str | None = Field(
        default=None,
        exclude=True,
        description="Logical dataset reference this action reads/writes (e.g. 'prod_customer_support_kb', S3 path, table name)",
    )

    @model_validator(mode="before")
    @classmethod
    def _lift_gdpr_fields_from_context(cls, value: Any) -> Any:
        """Lift wired GDPR fields out of an incoming ``context`` onto the model.

        Serialization nests ``purpose`` / ``data_categories`` / ``dataset_ref``
        under ``context`` (where Vault's typed ``RequestContext`` reads them), so
        ``model_validate_json(model_dump_json())`` must reverse that to keep the
        attribute round-trip intact. An explicit top-level kwarg always wins —
        we only lift when the top-level key is absent (an explicit
        ``purpose=None`` is honored as a deliberate suppression, not overwritten).
        """
        if not isinstance(value, dict):
            return value
        context = value.get("context")
        if not isinstance(context, dict):
            return value
        data = dict(value)
        for key in ("purpose", "data_categories", "dataset_ref"):
            if key in context and key not in data:
                data[key] = context[key]
        return data

    @model_serializer(mode="wrap")
    def _serialize_with_nested_gdpr(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        """Fold the wired GDPR fields into a copy of ``context`` at dump time.

        ``data_categories`` / ``purpose`` / ``dataset_ref`` are ``exclude=True``
        so the base handler omits them at top level; we merge them (when set)
        into the serialized ``context`` dict so they reach Vault's typed
        ``RequestContext``. ``processing_register_ref`` is never emitted —
        Vault's clearance wire has no field for it anywhere. When an attr is
        ``None`` we also strip any same-named key already in ``context`` so an
        explicit ``None`` suppresses a context-embedded value instead of leaking
        it onto the wire.
        """
        data = cast("dict[str, Any]", handler(self))
        context = dict(data.get("context") or {})
        if self.data_categories is not None:
            context["data_categories"] = self.data_categories
        else:
            context.pop("data_categories", None)
        if self.purpose is not None:
            context["purpose"] = self.purpose
        else:
            context.pop("purpose", None)
        if self.dataset_ref is not None:
            context["dataset_ref"] = self.dataset_ref
        else:
            context.pop("dataset_ref", None)
        data["context"] = context
        return data


ConfidenceBucket = Literal["extra_high", "high", "medium", "low", "none"]
DecisionStatus = Literal["approved", "denied", "approved_pending_review"]


class ClearanceResponse(BaseModel):
    """Response from the Vault's ``/request-clearance`` endpoint.

    As of v1.0 the wire format is bucket-only. The legacy ``approved``,
    ``confidence``, and ``minimum_confidence_score`` fields have been
    removed; consumers read ``decision_status`` and ``confidence_bucket``
    instead. See ``docs/MIGRATION_0.4.md`` for the migration guide.
    """

    status: str = Field(default="denied", description="Vault lifecycle: processing, approved, denied, or pending_review")
    decision_status: DecisionStatus = Field(
        default="denied",
        description="Categorical decision: approved | denied | approved_pending_review",
    )
    requires_manual_review: bool = Field(default=False, description="Whether the request is pending human review")
    token: str | None = Field(default=None, description="Signed A-JWT if approved, None if denied")
    reason: str = Field(default="", description="Human-readable explanation of the decision")
    request_id: str = Field(default="", description="Vault-assigned unique ID for this request")
    confidence_bucket: ConfidenceBucket = Field(
        default="none",
        description="Categorical confidence: extra_high | high | medium | low | none",
    )
    minimum_confidence_bucket: ConfidenceBucket = Field(
        default="high",
        description="Client-configured minimum confidence bucket for auto approval",
    )
    policy_version_id: str | None = Field(
        default=None,
        description="UUID of the policy version the decision was evaluated against",
    )
    policy_content_hash: str | None = Field(
        default=None,
        description="Content hash of the policy version the decision was evaluated against",
    )
    reason_code: str | None = Field(
        default=None,
        description="Machine-readable denial code, e.g. 'spend_cap_exceeded'",
    )
    latency_ms: float | None = Field(default=None, description="Judge-reported total latency in milliseconds, when available")

    @property
    def is_approved(self) -> bool:
        """Convenience: True iff the policy permits the action.

        Returns True for both ``approved`` and ``approved_pending_review``.
        Use this in place of the legacy ``approved`` boolean. Note that
        ``approved_pending_review`` does NOT mean the agent can proceed
        immediately — it means the policy permits the action subject to
        human review.
        """
        return self.decision_status in ("approved", "approved_pending_review")


class PolicyRegistration(BaseModel):
    """Payload for registering a policy with the Vault."""

    policy_id: str = Field(..., description="Unique identifier for the policy")
    description: str = Field(default="", description="Human-readable description of the policy")
    rules: list[str] = Field(
        default_factory=list,
        description="List of plain-English rules (e.g. 'Refunds must not exceed $100')",
    )
    tools: list[str] = Field(
        default_factory=list,
        description="Tool names this policy applies to (empty = all tools)",
    )


class PolicyRegistrationResponse(BaseModel):
    """Response from the Vault's ``/register-policy`` endpoint."""

    policy_id: str = Field(..., description="Confirmed policy ID")
    status: str = Field(default="registered", description="Registration status")
    message: str = Field(default="", description="Additional information")


class LedgerEntry(BaseModel):
    """Ledger entry returned by the Vault's ledger endpoints."""

    model_config = ConfigDict(populate_by_name=True)

    seq: int
    event_uuid: str
    request_id: str
    agent_id: str = ""
    policy_id: str = ""
    policy_version_id: str = ""
    policy_content_hash: str = ""
    intent_hash: str = ""
    tool_name: str
    tool_args: dict[str, Any] = Field(default_factory=dict)
    raw_tool_args: Any = Field(default_factory=lambda: _MISSING, exclude=True)
    action_category: str = ""
    action_metadata: dict[str, Any] = Field(default_factory=dict)
    raw_action_metadata: Any = Field(default_factory=lambda: _MISSING, exclude=True)
    reason: str = ""
    citations: list[dict[str, Any]] = Field(default_factory=list)
    raw_citations: Any = Field(default_factory=lambda: _MISSING, exclude=True)
    evidence_chunks: list[dict[str, Any]] = Field(default_factory=list)
    raw_evidence_chunks: Any = Field(default_factory=lambda: _MISSING, exclude=True)
    # Legacy float kept for canonical_version=1 hash verification of old rows.
    # New rows under canonical_version=2 also carry confidence_bucket and
    # decision_status as their canonical signal.
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Legacy bucket midpoint; prefer confidence_bucket")
    confidence_bucket: ConfidenceBucket | None = Field(
        default=None,
        description="Categorical confidence; populated for canonical_version>=2 events",
    )
    decision_status: DecisionStatus | None = Field(
        default=None,
        description="Categorical decision; populated for canonical_version>=2 events",
    )
    approved: bool = Field(
        default=False,
        description="Legacy boolean; derived for new rows. Prefer decision_status.",
    )
    accepted_at: str = Field(validation_alias=AliasChoices("accepted_at", "decided_at"))
    canonical_version: int = 1
    event_hash: str
    leaf_hash: str
    leaf_index: int | None = None
    checkpoint_id: int | None = None
    receipt_algorithm: str = Field(
        default="",
        validation_alias=AliasChoices("receipt_algorithm", "signature_algorithm"),
    )
    receipt_key_id: str = Field(
        default="",
        validation_alias=AliasChoices("receipt_key_id", "signer_key_id"),
    )
    receipt_signature: str = Field(
        default="",
        validation_alias=AliasChoices("receipt_signature", "row_signature"),
    )
    receipt_payload: str = Field(default="")

    @model_validator(mode="before")
    @classmethod
    def _capture_raw_verification_fields(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        data = dict(value)
        if "raw_tool_args" not in data and "tool_args" in data:
            data["raw_tool_args"] = data.get("tool_args")
        if "raw_action_metadata" not in data and "action_metadata" in data:
            data["raw_action_metadata"] = data.get("action_metadata")
        if "raw_citations" not in data and "citations" in data:
            data["raw_citations"] = data.get("citations")
        if "raw_evidence_chunks" not in data and "evidence_chunks" in data:
            data["raw_evidence_chunks"] = data.get("evidence_chunks")
        return data

    @field_validator("tool_args", "action_metadata", mode="before")
    @classmethod
    def _normalize_nullable_dicts(cls, value: Any) -> Any:
        if value is None:
            return {}
        return value

    @field_validator("citations", "evidence_chunks", mode="before")
    @classmethod
    def _normalize_nullable_lists(cls, value: Any) -> Any:
        if value is None:
            return []
        return value


class LedgerCheckpoint(BaseModel):
    """Signed checkpoint returned by the Vault."""

    model_config = ConfigDict(populate_by_name=True)

    checkpoint_id: int
    microblock_id: int = 0
    tree_size: int
    root_hash: str = Field(validation_alias=AliasChoices("root_hash", "head_row_hash"))
    checkpoint_hash: str = Field(
        validation_alias=AliasChoices("checkpoint_hash", "manifest_hash"),
    )
    prev_checkpoint_hash: str = Field(
        default="",
        validation_alias=AliasChoices("prev_checkpoint_hash", "prev_manifest_hash"),
    )
    signature_algorithm: str = Field(
        default="",
        validation_alias=AliasChoices("signature_algorithm", "signature_algorithm"),
    )
    signer_key_id: str = ""
    checkpoint_signature: str = Field(
        default="",
        validation_alias=AliasChoices("checkpoint_signature", "manifest_signature"),
    )
    checkpoint_payload: str = Field(
        default="",
        validation_alias=AliasChoices("checkpoint_payload", "manifest_payload"),
    )
    signed_at: str = Field(validation_alias=AliasChoices("signed_at", "generated_at", "period_start"))
    mmd_seconds: int = 30
    export_target: str = ""
    export_uri: str = ""
    export_status: str = ""
    exported_at: str | None = None


LedgerManifest = LedgerCheckpoint


class LedgerKeyVersion(BaseModel):
    key_id: str
    algorithm: str
    public_jwk: str = ""
    active_from: str
    retired_at: str | None = None
    attestation_payload: str = ""
    attestation_signature: str = ""
    attestation_key_id: str = ""
    attestation_status: str = ""


class InclusionProof(BaseModel):
    event_uuid: str
    request_id: str
    event_hash: str
    leaf_hash: str
    leaf_index: int
    tree_size: int
    path: list[str] = Field(default_factory=list)
    checkpoint: LedgerCheckpoint


class ConsistencyProof(BaseModel):
    from_checkpoint: LedgerCheckpoint
    to_checkpoint: LedgerCheckpoint
    path: list[str] = Field(default_factory=list)


class LedgerProofBundle(BaseModel):
    event: LedgerEntry
    inclusion: InclusionProof
    consistency: ConsistencyProof | None = None
    keys: list[LedgerKeyVersion] = Field(default_factory=list)


class LedgerVerificationResult(BaseModel):
    """Result of independent offline ledger verification."""

    intact: bool
    verified_entries: int
    verified_checkpoints: int = 0
    verified_manifests: int
    latest_leaf_hash: str | None = None
    latest_checkpoint_hash: str | None = None
    latest_manifest_hash: str | None = None
    coverage_note: str | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Evidence runtime (Phase 2)
# ---------------------------------------------------------------------------


class RegisterFactRequest(BaseModel):
    """Request to register an evidence fact extracted from a source tool result."""

    customer_id: str
    session_id: str = ""
    field: str
    value: Any = None
    source_type: str
    source_id: str = ""
    source_actor: str = ""
    scope: str = ""
    authority_level: str = ""
    is_inferred: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class RegisteredFact(BaseModel):
    """Vault response after registering a fact (value never returned raw)."""

    model_config = ConfigDict(extra="ignore")

    id: str = ""
    customer_id_hash: str = ""
    session_id: str = ""
    field: str = ""
    source_type: str = ""
    scope: str = ""
    authority_level: str = ""


class FactRef(BaseModel):
    fact_id: str


class EvidenceObligation(BaseModel):
    model_config = ConfigDict(extra="ignore")

    code: str
    fact_id: str = ""
    field: str = ""
    reason: str = ""


class EvidenceConflict(BaseModel):
    model_config = ConfigDict(extra="ignore")

    field: str = ""
    conflict_type: str = ""
    status: str = ""
    fact_id_a: str = ""
    fact_id_b: str = ""


class CheckActionRequest(BaseModel):
    """Request to evaluate a protected action against current evidence."""

    customer_id: str = ""
    session_id: str = ""
    mode: str = ""
    action_type: str
    workflow: str = ""
    facts: list[FactRef] = Field(default_factory=list)
    # WIRE NOTE: ``obligations`` is a RESPONSE-only concept — Vault has no
    # request field for it (it would be silently dropped). It is kept as an
    # attribute (so ``evidence.py`` can set it and the public API is unchanged)
    # but ``exclude=True`` so it never goes out on the check-action wire.
    obligations: list[str] = Field(default_factory=list, exclude=True)
    current_turn: int = 0
    context: dict[str, Any] = Field(default_factory=dict)


class OutputClaim(BaseModel):
    """A caller-declared provenance hint for a number in the response text.

    Optional — Vault grounds numbers deterministically against registered facts
    and contract formulas regardless. A declared claim is only an escape-hatch
    rung that must still reference a real authoritative fact to bind.
    """

    model_config = ConfigDict(extra="ignore")

    claim_text: str = ""
    claim_type: str = ""
    source_fact_id: str = ""
    source_type: str = ""
    source_field: str = ""
    value: str = ""


class CheckOutputRequest(BaseModel):
    """Request to verify that the numbers in an agent's customer-facing response
    are grounded in registered evidence (Phase 4 output grounding)."""

    customer_id: str = ""
    session_id: str = ""
    mode: str = ""
    action_type: str = ""
    workflow: str = ""
    response_text: str = ""
    facts: list[FactRef] = Field(default_factory=list)
    output_claims: list[OutputClaim] = Field(default_factory=list)
    current_turn: int = 0


class ChallengeSource(BaseModel):
    model_config = ConfigDict(extra="ignore")

    fact_id: str = ""
    field: str = ""
    source_type: str = ""
    value_redacted: str = ""
    authority_level: str = ""


class Challenge(BaseModel):
    """A host-native challenge to render in the host's own UI (Phase 3)."""

    model_config = ConfigDict(extra="ignore")

    challenge_id: str = ""
    check_id: str = ""
    action_type: str = ""
    customer_id_hash: str = ""
    reason: str = ""
    field: str = ""
    current_value_redacted: str = ""
    proposed_value_redacted: str = ""
    source_summaries: list[ChallengeSource] = Field(default_factory=list)
    allowed_resolutions: list[str] = Field(default_factory=list)
    required_resolver_role: str = ""
    status: str = ""
    original_action_reference: str = ""
    challenge_token: str = ""


class ChallengeResolution(BaseModel):
    """The host's decision for a challenge, returned by the challenge handler."""

    selected_resolution: str
    resolved_by: str
    resolver_role: str = ""


class ResolveChallengeRequest(BaseModel):
    """Trusted decision event posted to /v1/evidence/resolve-challenge."""

    challenge_id: str
    challenge_token: str
    selected_resolution: str
    resolved_by: str
    resolver_role: str = ""
    field: str = ""
    value: str = ""


class CheckActionResult(BaseModel):
    """Vault decision for a check-action / check-output call."""

    model_config = ConfigDict(extra="ignore")

    check_id: str = ""
    receipt_id: str = ""
    action_type: str = ""
    customer_id_hash: str = ""
    decision: str = "deny"
    reason: str = ""
    mode: str = ""
    policy_version: str = ""
    matched_rules: list[str] = Field(default_factory=list)
    obligations: list[EvidenceObligation] = Field(default_factory=list)
    conflicts: list[EvidenceConflict] = Field(default_factory=list)
    challenge: Challenge | None = None

    @property
    def is_allowed(self) -> bool:
        return self.decision in ("allow", "allow_with_obligations")


class GraphFact(BaseModel):
    model_config = ConfigDict(extra="ignore")

    fact_id: str = ""
    field: str = ""
    value_redacted: str = ""
    source_type: str = ""
    session_id: str = ""
    authority_level: str = ""
    scope: str = ""
    expired: bool = False
    in_conflict: bool = False


class EvidenceGraph(BaseModel):
    """Current evidence facts for a customer/session (GET /v1/evidence/graph)."""

    model_config = ConfigDict(extra="ignore")

    customer_id_hash: str = ""
    session_id: str = ""
    policy_version: str = ""
    facts: list[GraphFact] = Field(default_factory=list)
    conflicts: list[EvidenceConflict] = Field(default_factory=list)
