# Ledgix ALCV — Client
# Sync + async HTTP client for Vault communication and A-JWT verification

from __future__ import annotations

import json
import random
import time
import hashlib
import base64
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt

_RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429, 500, 502, 503, 504})

from .config import VaultConfig
from .exceptions import (
    ClearanceDeniedError,
    ManualReviewTimeoutError,
    PolicyRegistrationError,
    TokenVerificationError,
    VaultConnectionError,
)
from .models import (
    ClearanceRequest,
    ClearanceResponse,
    LedgerEntry,
    LedgerManifest,
    LedgerVerificationResult,
    PolicyRegistration,
    PolicyRegistrationResponse,
)


class LedgixClient:
    """Sync + async client for the ALCV Vault.

    Usage (sync)::

        client = LedgixClient()
        resp = client.request_clearance(ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45}))

    Usage (async)::

        client = LedgixClient()
        resp = await client.arequest_clearance(ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45}))
    """

    def __init__(self, config: VaultConfig | None = None) -> None:
        self.config = config or VaultConfig()
        self._sync_client: httpx.Client | None = None
        self._async_client: httpx.AsyncClient | None = None
        self._jwks_cache: dict[str, Any] | None = None

    # ------------------------------------------------------------------
    # Internal HTTP helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.config.vault_api_key:
            headers["X-Vault-API-Key"] = self.config.vault_api_key
        return headers

    def _get_sync_client(self) -> httpx.Client:
        if self._sync_client is None or self._sync_client.is_closed:
            self._sync_client = httpx.Client(
                base_url=self.config.vault_url,
                headers=self._headers(),
                timeout=self.config.vault_timeout,
            )
        return self._sync_client

    def _get_async_client(self) -> httpx.AsyncClient:
        if self._async_client is None or self._async_client.is_closed:
            self._async_client = httpx.AsyncClient(
                base_url=self.config.vault_url,
                headers=self._headers(),
                timeout=self.config.vault_timeout,
            )
        return self._async_client

    # ------------------------------------------------------------------
    # Retry helpers
    # ------------------------------------------------------------------

    def _backoff_delay(self, attempt: int) -> float:
        """Exponential backoff with full jitter, capped at 30 seconds."""
        delay = min(30.0, self.config.retry_base_delay * (2 ** attempt))
        return random.uniform(0.0, delay)

    def _sync_retry(self, fn: Callable[[], httpx.Response]) -> httpx.Response:
        """Execute an HTTP callable with retry and exponential backoff.

        Retries on ``httpx.TransportError`` (network errors, timeouts) and on
        retryable HTTP status codes (429, 5xx). Raises ``VaultConnectionError``
        after all attempts are exhausted.
        """
        last_exc: httpx.TransportError | None = None
        response: httpx.Response | None = None
        for attempt in range(self.config.max_retries + 1):
            try:
                response = fn()
            except httpx.TransportError as exc:
                last_exc = exc
                if attempt < self.config.max_retries:
                    time.sleep(self._backoff_delay(attempt))
                    continue
                raise VaultConnectionError(str(exc)) from exc
            if response.status_code in _RETRYABLE_STATUS_CODES and attempt < self.config.max_retries:
                time.sleep(self._backoff_delay(attempt))
                continue
            return response
        if last_exc is not None:
            raise VaultConnectionError(str(last_exc)) from last_exc
        assert response is not None
        return response

    async def _async_retry(self, fn: Callable[[], Awaitable[httpx.Response]]) -> httpx.Response:
        """Async variant of ``_sync_retry``."""
        import asyncio

        last_exc: httpx.TransportError | None = None
        response: httpx.Response | None = None
        for attempt in range(self.config.max_retries + 1):
            try:
                response = await fn()
            except httpx.TransportError as exc:
                last_exc = exc
                if attempt < self.config.max_retries:
                    await asyncio.sleep(self._backoff_delay(attempt))
                    continue
                raise VaultConnectionError(str(exc)) from exc
            if response.status_code in _RETRYABLE_STATUS_CODES and attempt < self.config.max_retries:
                await asyncio.sleep(self._backoff_delay(attempt))
                continue
            return response
        if last_exc is not None:
            raise VaultConnectionError(str(last_exc)) from last_exc
        assert response is not None
        return response

    # ------------------------------------------------------------------
    # Clearance — sync
    # ------------------------------------------------------------------

    def request_clearance(self, request: ClearanceRequest) -> ClearanceResponse:
        """Send a clearance request to the Vault (sync).

        Raises:
            ClearanceDeniedError: If the Vault denies the request.
            VaultConnectionError: If the Vault is unreachable.
        """
        try:
            response = self._sync_retry(
                lambda: self._get_sync_client().post(
                    "/request-clearance",
                    content=request.model_dump_json(),
                )
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise VaultConnectionError(
                f"Vault returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc

        clearance = ClearanceResponse.model_validate(response.json())
        clearance = self._resolve_pending_clearance(clearance)

        if not clearance.approved:
            raise ClearanceDeniedError(
                reason=clearance.reason,
                request_id=clearance.request_id,
            )

        if self.config.verify_jwt and clearance.token:
            self.verify_token(clearance.token)

        return clearance

    # ------------------------------------------------------------------
    # Clearance — async
    # ------------------------------------------------------------------

    async def arequest_clearance(self, request: ClearanceRequest) -> ClearanceResponse:
        """Send a clearance request to the Vault (async).

        Raises:
            ClearanceDeniedError: If the Vault denies the request.
            VaultConnectionError: If the Vault is unreachable.
        """
        try:
            response = await self._async_retry(
                lambda: self._get_async_client().post(
                    "/request-clearance",
                    content=request.model_dump_json(),
                )
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise VaultConnectionError(
                f"Vault returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc

        clearance = ClearanceResponse.model_validate(response.json())
        clearance = await self._aresolve_pending_clearance(clearance)

        if not clearance.approved:
            raise ClearanceDeniedError(
                reason=clearance.reason,
                request_id=clearance.request_id,
            )

        if self.config.verify_jwt and clearance.token:
            await self.averify_token(clearance.token)

        return clearance

    # ------------------------------------------------------------------
    # Policy registration
    # ------------------------------------------------------------------

    def register_policy(self, policy: PolicyRegistration) -> PolicyRegistrationResponse:
        """Register a policy with the Vault (sync)."""
        try:
            response = self._sync_retry(
                lambda: self._get_sync_client().post(
                    "/register-policy",
                    content=policy.model_dump_json(),
                )
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise PolicyRegistrationError(
                f"Vault returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc

        return PolicyRegistrationResponse.model_validate(response.json())

    async def aregister_policy(self, policy: PolicyRegistration) -> PolicyRegistrationResponse:
        """Register a policy with the Vault (async)."""
        try:
            response = await self._async_retry(
                lambda: self._get_async_client().post(
                    "/register-policy",
                    content=policy.model_dump_json(),
                )
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise PolicyRegistrationError(
                f"Vault returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc

        return PolicyRegistrationResponse.model_validate(response.json())

    # ------------------------------------------------------------------
    # JWKS + A-JWT verification
    # ------------------------------------------------------------------

    def _resolve_pending_clearance(self, clearance: ClearanceResponse) -> ClearanceResponse:
        if clearance.status not in {"processing", "pending_review"}:
            return clearance

        deadline = time.monotonic() + self.config.review_timeout
        while time.monotonic() < deadline:
            time.sleep(self.config.review_poll_interval)
            response = self._get_sync_client().get(f"/clearance-status/{clearance.request_id}")
            response.raise_for_status()
            clearance = ClearanceResponse.model_validate(response.json())
            if clearance.status not in {"processing", "pending_review"}:
                return clearance
        raise ManualReviewTimeoutError(clearance.request_id)

    async def _aresolve_pending_clearance(self, clearance: ClearanceResponse) -> ClearanceResponse:
        if clearance.status not in {"processing", "pending_review"}:
            return clearance

        import asyncio

        deadline = time.monotonic() + self.config.review_timeout
        while time.monotonic() < deadline:
            await asyncio.sleep(self.config.review_poll_interval)
            response = await self._get_async_client().get(f"/clearance-status/{clearance.request_id}")
            response.raise_for_status()
            clearance = ClearanceResponse.model_validate(response.json())
            if clearance.status not in {"processing", "pending_review"}:
                return clearance
        raise ManualReviewTimeoutError(clearance.request_id)

    def fetch_jwks(self) -> dict[str, Any]:
        """Fetch the Vault's JWKS (JSON Web Key Set) for token verification (sync)."""
        try:
            response = self._sync_retry(
                lambda: self._get_sync_client().get("/.well-known/jwks.json")
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise VaultConnectionError(
                f"Failed to fetch JWKS: HTTP {exc.response.status_code}"
            ) from exc

        self._jwks_cache = response.json()
        return self._jwks_cache

    async def afetch_jwks(self) -> dict[str, Any]:
        """Fetch the Vault's JWKS for token verification (async)."""
        try:
            response = await self._async_retry(
                lambda: self._get_async_client().get("/.well-known/jwks.json")
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise VaultConnectionError(
                f"Failed to fetch JWKS: HTTP {exc.response.status_code}"
            ) from exc

        self._jwks_cache = response.json()
        return self._jwks_cache

    def fetch_ledger(self, limit: int = 100) -> list[LedgerEntry]:
        """Fetch recent ledger entries for the authenticated tenant (sync)."""
        query = urlencode({"limit": max(1, min(limit, 500))})
        try:
            response = self._sync_retry(lambda: self._get_sync_client().get(f"/ledger?{query}"))
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise VaultConnectionError(
                f"Failed to fetch ledger: HTTP {exc.response.status_code}"
            ) from exc

        payload = response.json()
        return [LedgerEntry.model_validate(item) for item in payload.get("entries", [])]

    async def afetch_ledger(self, limit: int = 100) -> list[LedgerEntry]:
        """Fetch recent ledger entries for the authenticated tenant (async)."""
        query = urlencode({"limit": max(1, min(limit, 500))})
        try:
            response = await self._async_retry(lambda: self._get_async_client().get(f"/ledger?{query}"))
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise VaultConnectionError(
                f"Failed to fetch ledger: HTTP {exc.response.status_code}"
            ) from exc

        payload = response.json()
        return [LedgerEntry.model_validate(item) for item in payload.get("entries", [])]

    def fetch_ledger_manifests(self, limit: int = 24) -> list[LedgerManifest]:
        """Fetch recent signed ledger manifests for the authenticated tenant (sync)."""
        query = urlencode({"limit": max(1, min(limit, 500))})
        try:
            response = self._sync_retry(
                lambda: self._get_sync_client().get(f"/ledger/manifests?{query}")
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise VaultConnectionError(
                f"Failed to fetch ledger manifests: HTTP {exc.response.status_code}"
            ) from exc

        payload = response.json()
        return [LedgerManifest.model_validate(item) for item in payload.get("manifests", [])]

    async def afetch_ledger_manifests(self, limit: int = 24) -> list[LedgerManifest]:
        """Fetch recent signed ledger manifests for the authenticated tenant (async)."""
        query = urlencode({"limit": max(1, min(limit, 500))})
        try:
            response = await self._async_retry(
                lambda: self._get_async_client().get(f"/ledger/manifests?{query}")
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise VaultConnectionError(
                f"Failed to fetch ledger manifests: HTTP {exc.response.status_code}"
            ) from exc

        payload = response.json()
        return [LedgerManifest.model_validate(item) for item in payload.get("manifests", [])]

    def verify_ledger_proof(
        self,
        entries: list[LedgerEntry | dict[str, Any]] | None = None,
        manifests: list[LedgerManifest | dict[str, Any]] | None = None,
    ) -> LedgerVerificationResult:
        """Verify ledger row receipts and manifest signatures offline using the Vault JWKS."""
        entries = (
            [item if isinstance(item, LedgerEntry) else LedgerEntry.model_validate(item) for item in entries]
            if entries is not None
            else self.fetch_ledger()
        )
        manifests = (
            [item if isinstance(item, LedgerManifest) else LedgerManifest.model_validate(item) for item in manifests]
            if manifests is not None
            else self.fetch_ledger_manifests()
        )
        if self._jwks_cache is None:
            self.fetch_jwks()
        return self._verify_ledger_proof(entries, manifests)

    async def averify_ledger_proof(
        self,
        entries: list[LedgerEntry | dict[str, Any]] | None = None,
        manifests: list[LedgerManifest | dict[str, Any]] | None = None,
    ) -> LedgerVerificationResult:
        """Async variant of ``verify_ledger_proof``."""
        entries = (
            [item if isinstance(item, LedgerEntry) else LedgerEntry.model_validate(item) for item in entries]
            if entries is not None
            else await self.afetch_ledger()
        )
        manifests = (
            [item if isinstance(item, LedgerManifest) else LedgerManifest.model_validate(item) for item in manifests]
            if manifests is not None
            else await self.afetch_ledger_manifests()
        )
        if self._jwks_cache is None:
            await self.afetch_jwks()
        return self._verify_ledger_proof(entries, manifests)

    def verify_token(self, token: str) -> dict[str, Any]:
        """Verify an A-JWT using the Vault's public key (sync).

        Returns the decoded token payload on success.

        Raises:
            TokenVerificationError: If the token is invalid, expired, or
                the JWKS cannot be fetched.
        """
        if self._jwks_cache is None:
            self.fetch_jwks()
        return self._decode_token(token)

    async def averify_token(self, token: str) -> dict[str, Any]:
        """Verify an A-JWT using the Vault's public key (async).

        Raises:
            TokenVerificationError: If the token is invalid, expired, or
                the JWKS cannot be fetched.
        """
        if self._jwks_cache is None:
            await self.afetch_jwks()
        return self._decode_token(token)

    def _decode_token(self, token: str) -> dict[str, Any]:
        """Verify an A-JWT against the cached JWKS. JWKS must already be populated."""
        if not self._jwks_cache:
            raise TokenVerificationError("No JWKS available from Vault")

        try:
            jwks = self._jwks_cache
            if "keys" not in jwks or not jwks["keys"]:
                raise TokenVerificationError("JWKS contains no keys")

            key_data = jwks["keys"][0]
            public_key = jwt.algorithms.OKPAlgorithm.from_jwk(json.dumps(key_data))

            decoded = jwt.decode(
                token,
                public_key,
                algorithms=["EdDSA"],
                audience=self.config.jwt_audience,
                issuer=self.config.jwt_issuer,
                options={"verify_exp": True, "require": ["exp", "iss", "aud", "sub"]},
            )
            if decoded.get("sub") != "clearance":
                raise TokenVerificationError("Invalid A-JWT: unexpected subject")
            return decoded

        except TokenVerificationError:
            raise
        except jwt.ExpiredSignatureError as exc:
            raise TokenVerificationError("A-JWT has expired") from exc
        except jwt.InvalidTokenError as exc:
            raise TokenVerificationError(f"Invalid A-JWT: {exc}") from exc
        except Exception as exc:
            raise TokenVerificationError(f"Token verification failed: {exc}") from exc

    def _verify_ledger_proof(
        self,
        entries: list[LedgerEntry],
        manifests: list[LedgerManifest],
    ) -> LedgerVerificationResult:
        if not self._jwks_cache:
            return LedgerVerificationResult(
                intact=False,
                verified_entries=0,
                verified_manifests=0,
                latest_row_hash=None,
                latest_manifest_hash=None,
                error="No JWKS available from Vault",
            )

        try:
            jwks = self._jwks_cache
            keys = jwks.get("keys") if isinstance(jwks, dict) else None
            if not isinstance(keys, list) or not keys:
                raise TokenVerificationError("JWKS contains no keys")

            algorithm = jwt.algorithms.get_default_algorithms()["EdDSA"]
            key_cache: dict[str, Any] = {}

            def key_for_kid(kid: str) -> Any:
                if kid in key_cache:
                    return key_cache[kid]
                match = next(
                    (
                        item
                        for item in keys
                        if isinstance(item, dict) and item.get("kid") == kid
                    ),
                    None,
                )
                if match is None:
                    raise TokenVerificationError(f"No public key found for kid {kid}")
                public_key = jwt.algorithms.OKPAlgorithm.from_jwk(json.dumps(match))
                key_cache[kid] = public_key
                return public_key

            previous_row_hash = "0" * 64
            sorted_entries = sorted(entries, key=lambda item: item.seq)
            for entry in sorted_entries:
                if entry.prev_row_hash != previous_row_hash:
                    raise TokenVerificationError(f"Ledger chain broken at seq {entry.seq}")
                if not entry.receipt_payload or not entry.row_signature or not entry.signer_key_id:
                    raise TokenVerificationError(f"Missing receipt proof data at seq {entry.seq}")
                if not algorithm.verify(
                    self._decode_base64url(entry.receipt_payload),
                    key_for_kid(entry.signer_key_id),
                    self._decode_base64url(entry.row_signature),
                ):
                    raise TokenVerificationError(f"Ledger receipt signature invalid at seq {entry.seq}")
                previous_row_hash = entry.row_hash

            previous_manifest_hash = "sha256:" + ("0" * 64)
            sorted_manifests = sorted(manifests, key=lambda item: item.period_start)
            for manifest in sorted_manifests:
                if manifest.prev_manifest_hash != previous_manifest_hash:
                    raise TokenVerificationError(
                        f"Manifest chain broken at {manifest.period_start}"
                    )
                if not manifest.manifest_payload or not manifest.manifest_signature or not manifest.signer_key_id:
                    raise TokenVerificationError(
                        f"Missing manifest proof data at {manifest.period_start}"
                    )
                payload_bytes = self._decode_base64url(manifest.manifest_payload)
                if not algorithm.verify(
                    payload_bytes,
                    key_for_kid(manifest.signer_key_id),
                    self._decode_base64url(manifest.manifest_signature),
                ):
                    raise TokenVerificationError(
                        f"Manifest signature invalid at {manifest.period_start}"
                    )
                payload_hash = hashlib.sha256(payload_bytes).hexdigest()
                if f"sha256:{payload_hash}" != manifest.manifest_hash:
                    raise TokenVerificationError(
                        f"Manifest hash mismatch at {manifest.period_start}"
                    )
                previous_manifest_hash = manifest.manifest_hash

            return LedgerVerificationResult(
                intact=True,
                verified_entries=len(sorted_entries),
                verified_manifests=len(sorted_manifests),
                latest_row_hash=sorted_entries[-1].row_hash if sorted_entries else None,
                latest_manifest_hash=sorted_manifests[-1].manifest_hash if sorted_manifests else None,
            )
        except Exception as exc:
            return LedgerVerificationResult(
                intact=False,
                verified_entries=0,
                verified_manifests=0,
                latest_row_hash=None,
                latest_manifest_hash=None,
                error=str(exc),
            )

    @staticmethod
    def _decode_base64url(value: str) -> bytes:
        padded = value + "=" * ((4 - len(value) % 4) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying HTTP clients."""
        if self._sync_client and not self._sync_client.is_closed:
            self._sync_client.close()
        if self._async_client and not self._async_client.is_closed:
            # Can't await in sync context; schedule close if event loop exists
            import asyncio

            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._async_client.aclose())
            except RuntimeError:
                pass  # No running loop; client will be GC'd

    async def aclose(self) -> None:
        """Close the underlying HTTP clients (async)."""
        if self._sync_client and not self._sync_client.is_closed:
            self._sync_client.close()
        if self._async_client and not self._async_client.is_closed:
            await self._async_client.aclose()

    def __enter__(self) -> LedgixClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    async def __aenter__(self) -> LedgixClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()
