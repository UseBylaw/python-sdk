# Ledgix ALCV — Client
# Sync + async HTTP client for Vault communication and A-JWT verification

from __future__ import annotations

import base64
import hashlib
import json
import math
import random
import struct
import time
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
    ConsistencyProof,
    InclusionProof,
    LedgerEntry,
    LedgerCheckpoint,
    LedgerKeyVersion,
    LedgerProofBundle,
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

    def fetch_ledger_checkpoints(self, limit: int = 24) -> list[LedgerCheckpoint]:
        """Fetch recent signed ledger checkpoints for the authenticated tenant (sync)."""
        query = urlencode({"limit": max(1, min(limit, 500))})
        try:
            response = self._sync_retry(
                lambda: self._get_sync_client().get(f"/ledger/checkpoints?{query}")
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise VaultConnectionError(
                f"Failed to fetch ledger checkpoints: HTTP {exc.response.status_code}"
            ) from exc

        payload = response.json()
        return [LedgerCheckpoint.model_validate(item) for item in payload.get("checkpoints", [])]

    async def afetch_ledger_checkpoints(self, limit: int = 24) -> list[LedgerCheckpoint]:
        """Fetch recent signed ledger checkpoints for the authenticated tenant (async)."""
        query = urlencode({"limit": max(1, min(limit, 500))})
        try:
            response = await self._async_retry(
                lambda: self._get_async_client().get(f"/ledger/checkpoints?{query}")
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise VaultConnectionError(
                f"Failed to fetch ledger checkpoints: HTTP {exc.response.status_code}"
            ) from exc

        payload = response.json()
        return [LedgerCheckpoint.model_validate(item) for item in payload.get("checkpoints", [])]

    def fetch_ledger_manifests(self, limit: int = 24) -> list[LedgerManifest]:
        return self.fetch_ledger_checkpoints(limit)

    async def afetch_ledger_manifests(self, limit: int = 24) -> list[LedgerManifest]:
        return await self.afetch_ledger_checkpoints(limit)

    def fetch_ledger_inclusion_proof(self, request_id: str) -> InclusionProof:
        response = self._sync_retry(
            lambda: self._get_sync_client().get(f"/ledger/proof/inclusion?request_id={request_id}")
        )
        response.raise_for_status()
        return InclusionProof.model_validate(response.json())

    async def afetch_ledger_inclusion_proof(self, request_id: str) -> InclusionProof:
        response = await self._async_retry(
            lambda: self._get_async_client().get(f"/ledger/proof/inclusion?request_id={request_id}")
        )
        response.raise_for_status()
        return InclusionProof.model_validate(response.json())

    def fetch_ledger_consistency_proof(self, from_checkpoint_id: int, to_checkpoint_id: int) -> ConsistencyProof:
        response = self._sync_retry(
            lambda: self._get_sync_client().get(
                f"/ledger/proof/consistency?from={from_checkpoint_id}&to={to_checkpoint_id}"
            )
        )
        response.raise_for_status()
        return ConsistencyProof.model_validate(response.json())

    async def afetch_ledger_consistency_proof(self, from_checkpoint_id: int, to_checkpoint_id: int) -> ConsistencyProof:
        response = await self._async_retry(
            lambda: self._get_async_client().get(
                f"/ledger/proof/consistency?from={from_checkpoint_id}&to={to_checkpoint_id}"
            )
        )
        response.raise_for_status()
        return ConsistencyProof.model_validate(response.json())

    def fetch_ledger_proof_bundle(self, request_id: str) -> LedgerProofBundle:
        response = self._sync_retry(
            lambda: self._get_sync_client().get(f"/ledger/proof/bundle?request_id={request_id}")
        )
        response.raise_for_status()
        return LedgerProofBundle.model_validate(response.json())

    async def afetch_ledger_proof_bundle(self, request_id: str) -> LedgerProofBundle:
        response = await self._async_retry(
            lambda: self._get_async_client().get(f"/ledger/proof/bundle?request_id={request_id}")
        )
        response.raise_for_status()
        return LedgerProofBundle.model_validate(response.json())

    def verify_ledger_proof(
        self,
        entries: list[LedgerEntry | dict[str, Any]] | None = None,
        manifests: list[LedgerManifest | dict[str, Any]] | None = None,
    ) -> LedgerVerificationResult:
        """Verify ledger event receipts and checkpoint signatures offline using the Vault JWKS."""
        entries = (
            [item if isinstance(item, LedgerEntry) else LedgerEntry.model_validate(item) for item in entries]
            if entries is not None
            else self.fetch_ledger()
        )
        checkpoints = (
            [item if isinstance(item, LedgerCheckpoint) else LedgerCheckpoint.model_validate(item) for item in manifests]
            if manifests is not None
            else self.fetch_ledger_checkpoints()
        )
        if self._jwks_cache is None:
            self.fetch_jwks()
        return self._verify_ledger_proof(entries, checkpoints)

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
        checkpoints = (
            [item if isinstance(item, LedgerCheckpoint) else LedgerCheckpoint.model_validate(item) for item in manifests]
            if manifests is not None
            else await self.afetch_ledger_checkpoints()
        )
        if self._jwks_cache is None:
            await self.afetch_jwks()
        return self._verify_ledger_proof(entries, checkpoints)

    def verify_ledger_proof_bundle(
        self,
        bundle: LedgerProofBundle | dict[str, Any],
    ) -> LedgerVerificationResult:
        proof_bundle = (
            bundle
            if isinstance(bundle, LedgerProofBundle)
            else LedgerProofBundle.model_validate(bundle)
        )
        if not proof_bundle.keys and self._jwks_cache is None:
            self.fetch_jwks()
        return self._verify_ledger_proof_bundle(proof_bundle)

    async def averify_ledger_proof_bundle(
        self,
        bundle: LedgerProofBundle | dict[str, Any],
    ) -> LedgerVerificationResult:
        proof_bundle = (
            bundle
            if isinstance(bundle, LedgerProofBundle)
            else LedgerProofBundle.model_validate(bundle)
        )
        if not proof_bundle.keys and self._jwks_cache is None:
            await self.afetch_jwks()
        return self._verify_ledger_proof_bundle(proof_bundle)

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
        checkpoints: list[LedgerCheckpoint],
        key_records: list[dict[str, Any]] | None = None,
    ) -> LedgerVerificationResult:
        verification_keys = key_records or self._resolve_verification_keys()
        if not verification_keys:
            return LedgerVerificationResult(
                intact=False,
                verified_entries=0,
                verified_checkpoints=0,
                verified_manifests=0,
                latest_leaf_hash=None,
                latest_checkpoint_hash=None,
                latest_manifest_hash=None,
                coverage_note=None,
                error="No JWKS available from Vault",
            )

        try:
            key_cache: dict[str, Any] = {}

            def key_for_kid(kid: str) -> Any:
                if kid in key_cache:
                    return key_cache[kid]
                match = next(
                    (
                        item
                        for item in verification_keys
                        if isinstance(item, dict) and item.get("kid") == kid
                    ),
                    None,
                )
                if match is None:
                    raise TokenVerificationError(f"No public key found for kid {kid}")
                public_key = jwt.algorithms.OKPAlgorithm.from_jwk(json.dumps(match))
                key_cache[kid] = public_key
                return public_key

            sorted_entries = sorted(entries, key=lambda item: item.seq)
            sequenced_entries = sorted(
                (entry for entry in sorted_entries if entry.leaf_index is not None),
                key=lambda item: item.leaf_index or 0,
            )

            latest_leaf_hash: str | None = None
            coverage_notes: list[str] = []
            redacted_entry_count = 0
            for entry in sorted_entries:
                if self._has_protected_event_fields(entry):
                    expected_event_hash = self._build_event_hash(entry)
                    if expected_event_hash != entry.event_hash:
                        raise TokenVerificationError(f"Ledger event hash mismatch at seq {entry.seq}")
                else:
                    redacted_entry_count += 1
                expected_leaf_hash = self._hash_leaf(entry.event_hash)
                if expected_leaf_hash != entry.leaf_hash:
                    raise TokenVerificationError(f"Ledger leaf hash mismatch at seq {entry.seq}")
                if entry.receipt_algorithm != "Ed25519":
                    raise TokenVerificationError(
                        f"Unsupported ledger receipt algorithm {entry.receipt_algorithm}"
                    )
                if not entry.receipt_payload or not entry.receipt_signature or not entry.receipt_key_id:
                    raise TokenVerificationError(f"Missing receipt proof data at seq {entry.seq}")
                payload_bytes = self._decode_base64url(entry.receipt_payload)
                rebuilt_payload = self._build_receipt_payload(entry)
                if payload_bytes != rebuilt_payload:
                    raise TokenVerificationError(f"Ledger receipt payload mismatch at seq {entry.seq}")
                key_for_kid(entry.receipt_key_id).verify(
                    self._decode_base64url(entry.receipt_signature),
                    payload_bytes,
                )
                latest_leaf_hash = entry.leaf_hash
            if redacted_entry_count > 0:
                coverage_notes.append(
                    "Event-body hash recomputation was skipped for "
                    f"{redacted_entry_count} redacted public ledger entr"
                    f"{'y' if redacted_entry_count == 1 else 'ies'}; receipt and checkpoint proofs still verified."
                )

            sorted_checkpoints = sorted(checkpoints, key=lambda item: item.checkpoint_id)
            previous_checkpoint_hash = ""
            latest_checkpoint_hash: str | None = None
            for checkpoint in sorted_checkpoints:
                if checkpoint.prev_checkpoint_hash != previous_checkpoint_hash:
                    raise TokenVerificationError(
                        f"Ledger checkpoint chain broken at checkpoint {checkpoint.checkpoint_id}"
                    )
                if checkpoint.signature_algorithm != "Ed25519":
                    raise TokenVerificationError(
                        f"Unsupported checkpoint signature algorithm {checkpoint.signature_algorithm}"
                    )
                if (
                    not checkpoint.checkpoint_payload
                    or not checkpoint.checkpoint_signature
                    or not checkpoint.signer_key_id
                ):
                    raise TokenVerificationError(
                        f"Missing checkpoint proof data at checkpoint {checkpoint.checkpoint_id}"
                    )
                payload_bytes = self._decode_base64url(checkpoint.checkpoint_payload)
                rebuilt_payload = self._build_checkpoint_payload(checkpoint)
                if payload_bytes != rebuilt_payload:
                    raise TokenVerificationError(
                        f"Ledger checkpoint payload mismatch at checkpoint {checkpoint.checkpoint_id}"
                    )
                if self._hash_checkpoint_payload(payload_bytes) != checkpoint.checkpoint_hash:
                    raise TokenVerificationError(
                        f"Ledger checkpoint hash mismatch at checkpoint {checkpoint.checkpoint_id}"
                    )
                key_for_kid(checkpoint.signer_key_id).verify(
                    self._decode_base64url(checkpoint.checkpoint_signature),
                    payload_bytes,
                )
                previous_checkpoint_hash = checkpoint.checkpoint_hash
                latest_checkpoint_hash = checkpoint.checkpoint_hash

            coverage_note: str | None = None
            if sorted_checkpoints:
                latest_checkpoint = sorted_checkpoints[-1]
                if len(sequenced_entries) == latest_checkpoint.tree_size:
                    root_hash = self._merkle_root([entry.leaf_hash for entry in sequenced_entries])
                    if root_hash != latest_checkpoint.root_hash:
                        raise TokenVerificationError(
                            "Latest checkpoint root does not match sequenced leaf hashes"
                        )
                else:
                    coverage_notes.append(
                        f"Provided {len(sequenced_entries)} sequenced entries for tree size "
                        f"{latest_checkpoint.tree_size}; full root verification requires the complete covered set."
                    )
            if coverage_notes:
                coverage_note = " ".join(coverage_notes)
            return LedgerVerificationResult(
                intact=True,
                verified_entries=len(sorted_entries),
                verified_checkpoints=len(sorted_checkpoints),
                verified_manifests=len(sorted_checkpoints),
                latest_leaf_hash=latest_leaf_hash,
                latest_checkpoint_hash=latest_checkpoint_hash,
                latest_manifest_hash=latest_checkpoint_hash,
                coverage_note=coverage_note,
            )
        except Exception as exc:
            return LedgerVerificationResult(
                intact=False,
                verified_entries=0,
                verified_checkpoints=0,
                verified_manifests=0,
                latest_leaf_hash=None,
                latest_checkpoint_hash=None,
                latest_manifest_hash=None,
                coverage_note=None,
                error=str(exc),
            )

    def _verify_ledger_proof_bundle(self, bundle: LedgerProofBundle) -> LedgerVerificationResult:
        verification_keys = self._resolve_verification_keys(bundle.keys)
        result = self._verify_ledger_proof(
            [bundle.event],
            [bundle.inclusion.checkpoint],
            key_records=verification_keys,
        )
        if not result.intact:
            return result
        if not self._verify_inclusion_proof(
            bundle.event.leaf_hash,
            bundle.inclusion.leaf_index,
            bundle.inclusion.tree_size,
            bundle.inclusion.path,
            bundle.inclusion.checkpoint.root_hash,
        ):
            return LedgerVerificationResult(
                intact=False,
                verified_entries=0,
                verified_checkpoints=0,
                verified_manifests=0,
                latest_leaf_hash=None,
                latest_checkpoint_hash=None,
                latest_manifest_hash=None,
                coverage_note=None,
                error="Ledger inclusion proof is invalid",
            )
        if bundle.consistency and not self._verify_consistency_proof(
            bundle.consistency.from_checkpoint.tree_size,
            bundle.consistency.to_checkpoint.tree_size,
            bundle.consistency.from_checkpoint.root_hash,
            bundle.consistency.to_checkpoint.root_hash,
            bundle.consistency.path,
        ):
            return LedgerVerificationResult(
                intact=False,
                verified_entries=0,
                verified_checkpoints=0,
                verified_manifests=0,
                latest_leaf_hash=None,
                latest_checkpoint_hash=None,
                latest_manifest_hash=None,
                coverage_note=None,
                error="Ledger consistency proof is invalid",
            )
        return LedgerVerificationResult(
            intact=True,
            verified_entries=1,
            verified_checkpoints=2 if bundle.consistency else 1,
            verified_manifests=2 if bundle.consistency else 1,
            latest_leaf_hash=bundle.event.leaf_hash,
            latest_checkpoint_hash=(
                bundle.consistency.to_checkpoint.checkpoint_hash
                if bundle.consistency
                else bundle.inclusion.checkpoint.checkpoint_hash
            ),
            latest_manifest_hash=(
                bundle.consistency.to_checkpoint.checkpoint_hash
                if bundle.consistency
                else bundle.inclusion.checkpoint.checkpoint_hash
            ),
            coverage_note=None,
        )

    def _resolve_verification_keys(
        self,
        embedded_keys: list[LedgerKeyVersion] | None = None,
    ) -> list[dict[str, Any]]:
        if embedded_keys:
            resolved: list[dict[str, Any]] = []
            for key_version in embedded_keys:
                if not key_version.public_jwk:
                    continue
                jwk = json.loads(self._decode_base64url(key_version.public_jwk).decode("utf-8"))
                if "kid" not in jwk or not jwk["kid"]:
                    jwk["kid"] = key_version.key_id
                resolved.append(jwk)
            if resolved:
                return resolved

        jwks = self._jwks_cache
        keys = jwks.get("keys") if isinstance(jwks, dict) else None
        if isinstance(keys, list):
            return [item for item in keys if isinstance(item, dict)]
        return []

    def _build_event_hash(self, entry: LedgerEntry) -> str:
        payload = self._encode_deterministic_cbor(
            {
                "accepted_at": entry.accepted_at,
                "agent_id": entry.agent_id,
                "approved": entry.approved,
                "canonical_version": entry.canonical_version,
                "citations": self._normalize_json_numbers_for_cbor(entry.citations),
                "confidence": entry.confidence,
                "event_uuid": entry.event_uuid,
                "evidence_chunks": self._normalize_json_numbers_for_cbor(entry.evidence_chunks),
                "intent_hash": entry.intent_hash,
                "policy_id": entry.policy_id,
                "reason": entry.reason,
                "request_id": entry.request_id,
                "tool_args": self._normalize_json_numbers_for_cbor(entry.tool_args),
                "tool_name": entry.tool_name,
            }
        )
        return self._hash_event_payload(payload)

    def _has_protected_event_fields(self, entry: LedgerEntry) -> bool:
        return isinstance(entry.intent_hash, str) and len(entry.intent_hash) > 0

    def _build_receipt_payload(self, entry: LedgerEntry) -> bytes:
        return self._encode_deterministic_cbor(
            {
                "accepted_at": entry.accepted_at,
                "event_hash": entry.event_hash,
                "event_uuid": entry.event_uuid,
                "leaf_hash": entry.leaf_hash,
                "receipt_key_id": entry.receipt_key_id,
                "request_id": entry.request_id,
                "type": "event_receipt",
                "version": 1,
            }
        )

    def _build_checkpoint_payload(self, checkpoint: LedgerCheckpoint) -> bytes:
        export_targets = [checkpoint.export_target] if checkpoint.export_target else []
        return self._encode_deterministic_cbor(
            {
                "export_targets": export_targets,
                "key_id": checkpoint.signer_key_id,
                "mmd_seconds": checkpoint.mmd_seconds,
                "prev_checkpoint_hash": checkpoint.prev_checkpoint_hash,
                "root_hash": checkpoint.root_hash,
                "signed_at": checkpoint.signed_at,
                "tree_size": checkpoint.tree_size,
                "type": "checkpoint",
                "version": 1,
            }
        )

    def _hash_event_payload(self, payload: bytes) -> str:
        return hashlib.sha256(b"ledgix.audit.event.v1\x00" + payload).hexdigest()

    def _hash_checkpoint_payload(self, payload: bytes) -> str:
        return hashlib.sha256(b"ledgix.audit.checkpoint.v1\x00" + payload).hexdigest()

    def _hash_leaf(self, event_hash: str) -> str:
        return hashlib.sha256(b"\x00" + bytes.fromhex(event_hash)).hexdigest()

    def _hash_node(self, left_hash: str, right_hash: str) -> str:
        return hashlib.sha256(
            b"\x01" + bytes.fromhex(left_hash) + bytes.fromhex(right_hash)
        ).hexdigest()

    def _merkle_root(self, leaf_hashes: list[str]) -> str:
        if not leaf_hashes:
            return ""
        return self._merkle_range_hash(leaf_hashes, 0, len(leaf_hashes))

    def _merkle_range_hash(self, leaf_hashes: list[str], start: int, size: int) -> str:
        if size == 1:
            return leaf_hashes[start]
        split = self._largest_power_of_two_less_than(size)
        left_hash = self._merkle_range_hash(leaf_hashes, start, split)
        right_hash = self._merkle_range_hash(leaf_hashes, start + split, size - split)
        return self._hash_node(left_hash, right_hash)

    @staticmethod
    def _largest_power_of_two_less_than(value: int) -> int:
        power = 1
        while power << 1 < value:
            power <<= 1
        return power

    def _verify_inclusion_proof(
        self,
        leaf_hash: str,
        leaf_index: int,
        tree_size: int,
        path: list[str],
        root_hash: str,
    ) -> bool:
        fn = leaf_index
        sn = tree_size - 1
        current_hash = leaf_hash
        for sibling in path:
            if sn == 0:
                return False
            if fn % 2 == 1 or fn == sn:
                current_hash = self._hash_node(sibling, current_hash)
                while fn > 0 and fn % 2 == 0:
                    fn >>= 1
                    sn >>= 1
            else:
                current_hash = self._hash_node(current_hash, sibling)
            fn >>= 1
            sn >>= 1
        return current_hash == root_hash and sn == 0

    def _verify_consistency_proof(
        self,
        first_size: int,
        second_size: int,
        first_hash: str,
        second_hash: str,
        path: list[str],
    ) -> bool:
        if first_size == second_size:
            return first_hash == second_hash
        if not path:
            return False
        working = [first_hash, *path] if self._is_power_of_two(first_size) else list(path)
        fn = first_size - 1
        sn = second_size - 1
        while fn & 1 == 1:
            fn >>= 1
            sn >>= 1
        first_root = working[0]
        second_root = working[0]
        for candidate in working[1:]:
            if sn == 0:
                return False
            if fn & 1 == 1 or fn == sn:
                first_root = self._hash_node(candidate, first_root)
                second_root = self._hash_node(candidate, second_root)
                while fn > 0 and fn & 1 == 0:
                    fn >>= 1
                    sn >>= 1
            else:
                second_root = self._hash_node(second_root, candidate)
            fn >>= 1
            sn >>= 1
        return first_root == first_hash and second_root == second_hash and sn == 0

    @staticmethod
    def _is_power_of_two(value: int) -> bool:
        return value > 0 and (value & (value - 1)) == 0

    def _normalize_json_numbers_for_cbor(self, value: Any) -> Any:
        if value is None or isinstance(value, (str, bool, float)):
            return value
        if isinstance(value, int):
            return float(value)
        if isinstance(value, (list, tuple)):
            return [self._normalize_json_numbers_for_cbor(item) for item in value]
        if isinstance(value, dict):
            return {key: self._normalize_json_numbers_for_cbor(item) for key, item in value.items()}
        return value

    def _encode_deterministic_cbor(self, value: Any) -> bytes:
        if value is None:
            return b"\xf6"
        if isinstance(value, bool):
            return b"\xf5" if value else b"\xf4"
        if isinstance(value, str):
            encoded = value.encode("utf-8")
            return self._cbor_header(3, len(encoded)) + encoded
        if isinstance(value, bytes):
            return self._cbor_header(2, len(value)) + value
        if isinstance(value, int):
            return self._cbor_int(value)
        if isinstance(value, float):
            if math.isnan(value) or math.isinf(value):
                raise ValueError(f"Unsupported floating-point value {value}")
            return b"\xfb" + struct.pack(">d", value)
        if isinstance(value, (list, tuple)):
            items = b"".join(self._encode_deterministic_cbor(item) for item in value)
            return self._cbor_header(4, len(value)) + items
        if isinstance(value, dict):
            keys = sorted(value.keys(), key=lambda item: (len(item), item))
            encoded_items = bytearray()
            for key in keys:
                encoded_items.extend(self._encode_deterministic_cbor(str(key)))
                encoded_items.extend(self._encode_deterministic_cbor(value[key]))
            return self._cbor_header(5, len(keys)) + bytes(encoded_items)
        normalized = json.loads(json.dumps(value))
        return self._encode_deterministic_cbor(normalized)

    def _cbor_int(self, value: int) -> bytes:
        if value >= 0:
            return self._cbor_header(0, value)
        return self._cbor_header(1, -(value + 1))

    def _cbor_header(self, major: int, value: int) -> bytes:
        if value <= 23:
            return bytes([(major << 5) | value])
        if value <= 0xFF:
            return bytes([(major << 5) | 24, value])
        if value <= 0xFFFF:
            return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
        if value <= 0xFFFFFFFF:
            return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
        return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")

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
