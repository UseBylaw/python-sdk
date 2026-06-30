# Bylaw ALCV — Python SDK
# Runtime enforcement SDK for AI agent actions
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

"""Bylaw ALCV runtime enforcement SDK for AI agent actions."""

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
from .evidence import (
    aguard_output,
    evidence_session,
    guard_output,
    set_challenge_handler,
    set_session_store,
)
from .exceptions import (
    BylawError,
    ClearanceDeniedError,
    EvidenceBlockedError,
    EvidenceError,
    ManualReviewTimeoutError,
    PolicyRegistrationError,
    QueueSaturatedError,
    ReplayDetectedError,
    ReviewPendingError,
    TokenVerificationError,
    VaultConnectionError,
)
from .manifest import EvidenceRule, Manifest, ManifestRule, load_manifest
from .models import (
    Challenge,
    ChallengeResolution,
    CheckActionRequest,
    CheckActionResult,
    CheckOutputRequest,
    ClearanceRequest,
    ClearanceResponse,
    ConsistencyProof,
    EvidenceChunk,
    EvidenceGraph,
    InclusionProof,
    LedgerCheckpoint,
    LedgerEntry,
    LedgerKeyVersion,
    LedgerManifest,
    LedgerProofBundle,
    LedgerVerificationResult,
    OutputClaim,
    PolicyRegistration,
    PolicyRegistrationResponse,
    RegisteredFact,
    RegisterFactRequest,
    ResolveChallengeRequest,
)
from .pending import PendingApproval
from .session_store import InMemorySessionStore, SessionEvidenceStore
from .webhook import verify_webhook

__version__ = "0.6.7"

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
    # Output grounding (Phase 4)
    "guard_output",
    "aguard_output",
    "CheckOutputRequest",
    "EvidenceChunk",
    "OutputClaim",
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
