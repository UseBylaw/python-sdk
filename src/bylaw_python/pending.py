# Bylaw ALCV — PendingApproval
# Handle for detached manual-review decisions

from __future__ import annotations

import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .client import BylawClient
    from .models import ClearanceResponse


class PendingApproval:
    """Handle for a clearance request that entered ``pending_review`` status.

    Obtained when ``review_mode="detach"`` is set on :class:`~bylaw_python.VaultConfig`
    and the Vault returns a ``pending_review`` response.

    Usage (async)::

        try:
            result = await client.arequest_clearance(request)
        except ReviewPendingError as exc:
            pending = exc.pending_approval
            # store pending.request_id, come back later
            result = await pending.wait_async(timeout=1800)

    Usage (sync)::

        try:
            result = client.request_clearance(request)
        except ReviewPendingError as exc:
            result = exc.pending_approval.wait(timeout=1800)
    """

    def __init__(
        self,
        request_id: str,
        client: BylawClient,
        initial_response: ClearanceResponse,
    ) -> None:
        self._request_id = request_id
        self._client = client
        self._initial_response = initial_response

    @property
    def request_id(self) -> str:
        """The Vault's unique ID for this clearance request."""
        return self._request_id

    def wait(self, timeout: float | None = None) -> ClearanceResponse:
        """Block until the reviewer decides, then return the :class:`ClearanceResponse`.

        Args:
            timeout: Maximum seconds to wait. Defaults to the client's
                ``review_timeout`` config value.

        Raises:
            ManualReviewTimeoutError: If no decision arrives within *timeout*.
            ClearanceDeniedError: If the reviewer denies the request.
        """
        from .exceptions import ClearanceDeniedError, ManualReviewTimeoutError
        from .models import ClearanceResponse as CR

        deadline = time.monotonic() + (timeout if timeout is not None else self._client.config.review_timeout)
        poll = self._client.config.review_poll_interval

        while time.monotonic() < deadline:
            time.sleep(poll)
            response = self._client._get_sync_client().get(
                f"/clearance-status/{self._request_id}"
            )
            response.raise_for_status()
            clearance = CR.model_validate(response.json())
            if clearance.status not in {"processing", "pending_review"}:
                if not clearance.is_approved:
                    raise ClearanceDeniedError(
                        reason=clearance.reason,
                        request_id=clearance.request_id,
                    )
                return clearance

        raise ManualReviewTimeoutError(self._request_id)

    async def wait_async(self, timeout: float | None = None) -> ClearanceResponse:
        """Async variant of :meth:`wait`."""
        import asyncio

        from .exceptions import ClearanceDeniedError, ManualReviewTimeoutError
        from .models import ClearanceResponse as CR

        deadline = time.monotonic() + (timeout if timeout is not None else self._client.config.review_timeout)
        poll = self._client.config.review_poll_interval

        while time.monotonic() < deadline:
            await asyncio.sleep(poll)
            response = await self._client._get_async_client().get(
                f"/clearance-status/{self._request_id}"
            )
            response.raise_for_status()
            clearance = CR.model_validate(response.json())
            if clearance.status not in {"processing", "pending_review"}:
                if not clearance.is_approved:
                    raise ClearanceDeniedError(
                        reason=clearance.reason,
                        request_id=clearance.request_id,
                    )
                return clearance

        raise ManualReviewTimeoutError(self._request_id)

    def cancel(self) -> None:
        """Cancel the pending review by posting a denial decision.

        Records a ``review.cancelled_by_agent`` entry in the Vault ledger.
        """
        self._client._get_sync_client().post(
            f"/reviews/{self._request_id}/decision",
            json={"approved": False, "review_reason": "cancelled by agent"},
        )

    async def acancel(self) -> None:
        """Async variant of :meth:`cancel`."""
        await self._client._get_async_client().post(
            f"/reviews/{self._request_id}/decision",
            json={"approved": False, "review_reason": "cancelled by agent"},
        )
