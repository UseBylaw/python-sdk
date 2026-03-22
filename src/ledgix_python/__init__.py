# Ledgix ALCV — Python SDK
# Agent-agnostic compliance shim for SOX 404 policy enforcement
#
# Usage:
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
from .enforce import VaultContext, vault_enforce
from .exceptions import (
    ClearanceDeniedError,
    ManualReviewTimeoutError,
    PolicyRegistrationError,
    LedgixError,
    TokenVerificationError,
    VaultConnectionError,
)
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

__version__ = "0.1.6"

__all__ = [
    # Core
    "LedgixClient",
    "VaultConfig",
    # Enforcement
    "vault_enforce",
    "VaultContext",
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
    "VaultConnectionError",
    "TokenVerificationError",
    "PolicyRegistrationError",
]
