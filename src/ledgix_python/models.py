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
