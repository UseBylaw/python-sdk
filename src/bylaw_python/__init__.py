# Bylaw ALCV — Python SDK
# Agent-agnostic compliance shim for SOX 404 policy enforcement
#
# Recommended usage:
#   import bylaw_python as bylaw
#
#   bylaw.configure(agent_id="finance-agent")
#
#   import tools
#
#   bylaw.configure(agent_id="finance-agent")
#   bylaw.auto_instrument(tools)
#
# Explicit API (advanced):
#   from bylaw_python import BylawClient, vault_enforce, VaultConfig
#
#   client = BylawClient()
#
#   @vault_enforce(client, tool_name="stripe_refund")
#   def process_refund(amount: float, reason: str, **kwargs):
#       token = kwargs.get("_clearance").token
#       ...

"""Bylaw ALCV — agent-agnostic compliance shim for SOX 404 enforcement."""

from .client import BylawClient
from .config import VaultConfig
from .enforce import (
    VaultContext,
    auto_instrument,
    configure,
    current_clearance,
    current_token,
    enforce,
    tool,
    vault_enforce,
)
from .evidence import evidence_session, set_challenge_handler, set_session_store
from .manifest import EvidenceRule, Manifest, ManifestRule, load_manifest
from .session_store import InMemorySessionStore, SessionEvidenceStore
from .exceptions import (
    ClearanceDeniedError,
    EvidenceBlockedError,
    EvidenceError,
    ManualReviewTimeoutError,
    PolicyRegistrationError,
    BylawError,
    QueueSaturatedError,
    ReplayDetectedError,
    ReviewPendingError,
    TokenVerificationError,
    VaultConnectionError,
)
from .pending import PendingApproval
from .webhook import verify_webhook
from .models import (
    Challenge,
    ChallengeResolution,
    CheckActionRequest,
    CheckActionResult,
    ClearanceRequest,
    ClearanceResponse,
    ConsistencyProof,
    EvidenceGraph,
    ResolveChallengeRequest,
    InclusionProof,
    LedgerCheckpoint,
    LedgerEntry,
    LedgerKeyVersion,
    LedgerManifest,
    LedgerProofBundle,
    LedgerVerificationResult,
    PolicyRegistration,
    PolicyRegistrationResponse,
    RegisterFactRequest,
    RegisteredFact,
)

__version__ = "0.7.0"

__all__ = [
    # Core
    "BylawClient",
    "VaultConfig",
    # Low-code API
    "configure",
    "enforce",
    "current_clearance",
    "current_token",
    # Manifest / auto-instrumentation
    "auto_instrument",
    "tool",
    "load_manifest",
    "Manifest",
    "ManifestRule",
    "EvidenceRule",
    # Evidence runtime (Phase 2)
    "evidence_session",
    "set_session_store",
    "set_challenge_handler",
    "InMemorySessionStore",
    "SessionEvidenceStore",
    "CheckActionRequest",
    "CheckActionResult",
    "Challenge",
    "ChallengeResolution",
    "ResolveChallengeRequest",
    "EvidenceGraph",
    "RegisterFactRequest",
    "RegisteredFact",
    # Explicit API
    "vault_enforce",
    "VaultContext",
    # Detach-mode / async approvals
    "PendingApproval",
    # Webhook verification
    "verify_webhook",
    # Models
    "ClearanceRequest",
    "ClearanceResponse",
    "ConsistencyProof",
    "InclusionProof",
    "LedgerCheckpoint",
    "LedgerEntry",
    "LedgerKeyVersion",
    "LedgerManifest",
    "LedgerProofBundle",
    "LedgerVerificationResult",
    "PolicyRegistration",
    "PolicyRegistrationResponse",
    # Exceptions
    "BylawError",
    "ClearanceDeniedError",
    "ManualReviewTimeoutError",
    "QueueSaturatedError",
    "ReviewPendingError",
    "VaultConnectionError",
    "TokenVerificationError",
    "ReplayDetectedError",
    "PolicyRegistrationError",
    "EvidenceError",
    "EvidenceBlockedError",
]
