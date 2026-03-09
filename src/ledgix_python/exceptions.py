# Ledgix ALCV — Exceptions
# All custom exceptions for the SDK

from __future__ import annotations


class LedgixError(Exception):
    """Base exception for all Ledgix SDK errors."""
    pass


class ClearanceDeniedError(LedgixError):
    """Raised when the Vault denies a tool-call clearance request.

    Attributes:
        reason: Human-readable denial reason from the Vault.
        request_id: The Vault's unique ID for this clearance request.
    """

    def __init__(self, reason: str, request_id: str | None = None) -> None:
        self.reason = reason
        self.request_id = request_id
        super().__init__(f"Clearance denied: {reason}")


class ManualReviewTimeoutError(LedgixError):
    """Raised when a pending manual review decision does not resolve before timeout."""

    def __init__(self, request_id: str | None = None) -> None:
        self.request_id = request_id
        suffix = f" ({request_id})" if request_id else ""
        super().__init__(f"Manual review timed out{suffix}")


class VaultConnectionError(LedgixError):
    """Raised when the SDK cannot reach the Vault server."""

    def __init__(self, message: str = "Unable to connect to the Vault server") -> None:
        super().__init__(message)


class TokenVerificationError(LedgixError):
    """Raised when A-JWT verification fails (bad signature, expired, etc.)."""

    def __init__(self, message: str = "Token verification failed") -> None:
        super().__init__(message)


class PolicyRegistrationError(LedgixError):
    """Raised when a policy registration request fails."""

    def __init__(self, message: str = "Policy registration failed") -> None:
        super().__init__(message)
