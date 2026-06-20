# Bylaw ALCV — Exceptions
# All custom exceptions for the SDK

from __future__ import annotations


class BylawError(Exception):
    """Base exception for all Bylaw SDK errors."""
    pass


class ClearanceDeniedError(BylawError):
    """Raised when the Vault denies a tool-call clearance request.

    Attributes:
        reason: Human-readable denial reason from the Vault.
        request_id: The Vault's unique ID for this clearance request.
    """

    def __init__(self, reason: str, request_id: str | None = None) -> None:
        self.reason = reason
        self.request_id = request_id
        super().__init__(f"Clearance denied: {reason}")


class ManualReviewTimeoutError(BylawError):
    """Raised when a pending manual review decision does not resolve before timeout."""

    def __init__(self, request_id: str | None = None) -> None:
        self.request_id = request_id
        suffix = f" ({request_id})" if request_id else ""
        super().__init__(f"Manual review timed out{suffix}")


class VaultConnectionError(BylawError):
    """Raised when the SDK cannot reach the Vault server."""

    def __init__(self, message: str = "Unable to connect to the Vault server") -> None:
        super().__init__(message)


class TokenVerificationError(BylawError):
    """Raised when A-JWT verification fails (bad signature, expired, etc.)."""

    def __init__(self, message: str = "Token verification failed") -> None:
        super().__init__(message)


class PolicyRegistrationError(BylawError):
    """Raised when a policy registration request fails."""

    def __init__(self, message: str = "Policy registration failed") -> None:
        super().__init__(message)


class ReplayDetectedError(TokenVerificationError):
    """Raised when an A-JWT jti has already been consumed by this SDK instance.

    Each A-JWT is single-use. Presenting the same token twice in the same
    process raises this error so callers cannot accidentally reuse a spent
    clearance. The SDK tracks jtis for the token's remaining TTL plus a
    30-second clock-skew buffer.
    """

    def __init__(self, jti: str | None = None) -> None:
        self.jti = jti
        suffix = f" (jti={jti})" if jti else ""
        super(TokenVerificationError, self).__init__(f"A-JWT replay detected{suffix}")


class QueueSaturatedError(BylawError):
    """Raised when Vault repeatedly responds with HTTP 429 (queue near capacity).

    Vault emits 429 + ``Retry-After`` from its proactive backpressure check
    (Scale & Reliability §2.1). The SDK honors the header and does NOT count
    these against the normal ``max_retries`` budget — they're cooperative
    backoff, not failures. After ``max_consecutive_429`` waves with no
    success, however, the SDK gives up with this error so callers can fail
    fast instead of looping indefinitely while the Vault is melting.

    Attributes:
        attempts: How many consecutive 429s were received before giving up.
        last_retry_after: The last ``Retry-After`` value the server emitted (seconds).
    """

    def __init__(self, attempts: int, last_retry_after: float | None = None) -> None:
        self.attempts = attempts
        self.last_retry_after = last_retry_after
        suffix = f" (last Retry-After={last_retry_after}s)" if last_retry_after is not None else ""
        super().__init__(
            f"Vault clearance queue saturated after {attempts} consecutive 429 responses{suffix}"
        )


class ReviewPendingError(BylawError):
    """Raised in ``review_mode="detach"`` when a clearance enters pending-review.

    The attached :attr:`pending_approval` handle lets the caller poll or cancel
    the review without blocking the current thread/coroutine.
    """

    def __init__(self, pending_approval: "Any") -> None:  # noqa: F821
        self.pending_approval = pending_approval
        super().__init__(f"Clearance pending review (request_id={pending_approval.request_id})")


class EvidenceError(BylawError):
    """Base for evidence-runtime failures (fact registration, check-action)."""


class EvidenceBlockedError(EvidenceError):
    """Raised in ``evidence_mode="enforce"`` when check-action denies a protected action.

    Attributes:
        reason: Human-readable reason from the evidence runtime.
        decision: The raw decision (``deny`` / ``review``).
        receipt_id: The receipt id recorded for this decision, if any.
    """

    def __init__(self, reason: str, decision: str = "deny", receipt_id: str | None = None) -> None:
        self.reason = reason
        self.decision = decision
        self.receipt_id = receipt_id
        super().__init__(f"Evidence check {decision}: {reason}")
