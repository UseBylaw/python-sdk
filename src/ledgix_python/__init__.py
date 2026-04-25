# Ledgix ALCV — Python SDK
# Agent-agnostic compliance shim for SOX 404 policy enforcement
#
# Recommended usage:
#   import ledgix_python as ledgix
#
#   ledgix.configure(agent_id="finance-agent")
#
#   import tools
#
#   ledgix.configure(agent_id="finance-agent")
#   ledgix.auto_instrument(tools)
#
# Explicit API (advanced):
#   from ledgix_python import LedgixClient, vault_enforce, VaultConfig
#
#   client = LedgixClient()
#
#   @vault_enforce(client, tool_name="stripe_refund")
#   def process_refund(amount: float, reason: str, **kwargs):
#       token = kwargs.get("_clearance").token
#       ...

"""Ledgix ALCV — agent-agnostic compliance shim for SOX 404 enforcement."""

from .client import LedgixClient
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
from .manifest import Manifest, ManifestRule, load_manifest
from .exceptions import (
    ClearanceDeniedError,
    ManualReviewTimeoutError,
    PolicyRegistrationError,
    LedgixError,
    QueueSaturatedError,
    ReplayDetectedError,
    ReviewPendingError,
    TokenVerificationError,
    VaultConnectionError,
)
from .pending import PendingApproval
from .webhook import verify_webhook
from .models import (
    ClearanceRequest,
    ClearanceResponse,
    ConsistencyProof,
    InclusionProof,
    LedgerCheckpoint,
    LedgerEntry,
    LedgerKeyVersion,
    LedgerManifest,
    LedgerProofBundle,
    LedgerVerificationResult,
    PolicyRegistration,
    PolicyRegistrationResponse,
)

__version__ = "0.3.1"

__all__ = [
    # Core
    "LedgixClient",
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
    "LedgixError",
    "ClearanceDeniedError",
    "ManualReviewTimeoutError",
    "QueueSaturatedError",
    "ReviewPendingError",
    "VaultConnectionError",
    "TokenVerificationError",
    "ReplayDetectedError",
    "PolicyRegistrationError",
]
