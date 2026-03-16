# Ledgix ALCV — Data Models
# Pydantic models for Vault API request/response payloads

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


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


class ClearanceResponse(BaseModel):
    """Response from the Vault's ``/request-clearance`` endpoint."""

    status: str = Field(default="denied", description="Decision state: processing, approved, denied, or pending_review")
    approved: bool = Field(..., description="Whether the tool call was approved")
    requires_manual_review: bool = Field(default=False, description="Whether the request is pending human review")
    token: str | None = Field(default=None, description="Signed A-JWT if approved, None if denied")
    reason: str = Field(default="", description="Human-readable explanation of the decision")
    request_id: str = Field(default="", description="Vault-assigned unique ID for this request")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Judge confidence score")
    minimum_confidence_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Client-configured minimum confidence score for auto approval",
    )


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

    seq: int
    request_id: str
    agent_id: str = ""
    policy_id: str = ""
    intent_hash: str = ""
    tool_name: str
    tool_args: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""
    citations: list[dict[str, Any]] = Field(default_factory=list)
    evidence_chunks: list[dict[str, Any]] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    approved: bool
    decided_at: str
    prev_row_hash: str = ""
    row_hash: str
    signature_algorithm: str = ""
    signer_key_id: str = ""
    row_signature: str = ""
    receipt_payload: str = ""


class LedgerManifest(BaseModel):
    """Signed chain-head manifest returned by the Vault."""

    period_start: str
    period_end_exclusive: str
    generated_at: str
    head_seq: int
    head_row_hash: str
    head_row_signature: str = ""
    manifest_hash: str
    prev_manifest_hash: str = ""
    signature_algorithm: str = ""
    signer_key_id: str = ""
    manifest_signature: str = ""
    manifest_payload: str = ""
    anchor_uri: str = ""
    anchored_at: str | None = None


class LedgerVerificationResult(BaseModel):
    """Result of independent offline ledger verification."""

    intact: bool
    verified_entries: int
    verified_manifests: int
    latest_row_hash: str | None = None
    latest_manifest_hash: str | None = None
    legacy_unsigned_entries: int = 0
    coverage_note: str | None = None
    error: str | None = None
