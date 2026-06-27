# Bylaw ALCV — Client
# Sync + async HTTP client for Vault communication and A-JWT verification

from __future__ import annotations

import base64
import hashlib
import json
import math
import random
import struct
import threading
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt

_RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429, 500, 502, 503, 504})

# Vault's proactive backpressure (Scale & Reliability §2.1) emits 429 +
# Retry-After when its clearance queue is past the configured watermark. We
# honor the header verbatim (capped to MAX_RETRY_AFTER_SECONDS so a misbehaving
# server can't pin the SDK for minutes), and we do NOT count these waves
# against max_retries — they're cooperative backoff, not transport failures.
# A separate ceiling MAX_CONSECUTIVE_429 prevents an infinite loop if the
# Vault is genuinely melting.
MAX_RETRY_AFTER_SECONDS: float = 60.0
MAX_CONSECUTIVE_429: int = 10

from .config import VaultConfig
from .exceptions import (
    ClearanceDeniedError,
    EvidenceError,
    ManualReviewTimeoutError,
    PolicyRegistrationError,
    QueueSaturatedError,
    ReplayDetectedError,
    ReviewPendingError,
    TokenVerificationError,
    VaultConnectionError,
)


def _parse_retry_after(value: str | None) -> float | None:
    """Parse a Retry-After header value. Vault emits seconds; the HTTP spec
    also allows HTTP-date but we don't need that today. Returns None on parse
    failure so callers fall back to jittered backoff."""
    if not value:
        return None
    try:
        secs = float(value.strip())
    except (TypeError, ValueError):
        return None
    if secs < 0:
        return None
    return min(secs, MAX_RETRY_AFTER_SECONDS)
from .pending import PendingApproval
from .models import (
    Challenge,
    CheckActionRequest,
    CheckActionResult,
    CheckOutputRequest,
    ClearanceRequest,
    ClearanceResponse,
    ConsistencyProof,
    EvidenceGraph,
    ResolveChallengeRequest,
    InclusionProof,
    LedgerEntry,
    LedgerCheckpoint,
    LedgerKeyVersion,
    LedgerProofBundle,
    LedgerManifest,
    LedgerVerificationResult,
    PolicyRegistration,
    PolicyRegistrationResponse,
    RegisterFactRequest,
    RegisteredFact,
    _MISSING,
)
from .otel import current_otel_metadata, inject_otel_headers, record_clearance_event


class BylawClient:
    """Sync + async client for the ALCV Vault.

    Usage (sync)::

        client = BylawClient()
        resp = client.request_clearance(ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45}))

    Usage (async)::

        client = BylawClient()
        resp = await client.arequest_clearance(ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 45}))
    """

    def __init__(self, config: VaultConfig | None = None, *, _parent_jti: str | None = None) -> None:
        self.config = config or VaultConfig()
        self._parent_jti = _parent_jti
        self._sync_client: httpx.Client | None = None
        self._async_client: httpx.AsyncClient | None = None
        # JWKS cache: maps kid -> JWK dict. _jwks_fetched_at tracks when it was last populated.
        self._jwks_cache: dict[str, Any] | None = None  # raw JWKS response
        self._jwks_keys_by_kid: dict[str, Any] = {}     # kid -> JWK entry, rebuilt on each fetch
        self._jwks_fetched_at: float = 0.0
        self._decision_cache: Any = None  # cachetools.TTLCache or None
        self._decision_cache_lock = threading.Lock()
        from cachetools import TTLCache  # already a hard dep via decision_cache path
        self._seen_jtis: TTLCache = TTLCache(
            maxsize=self.config.replay_cache_size,
            ttl=self.config.max_token_lifetime_seconds,
        )
        self._seen_jtis_lock = threading.Lock()
        # Async lock is created lazily because constructing asyncio.Lock outside
        # a running event loop is fine in 3.10+ but we still defer to be safe
        # across event-loop swaps in the same process.
        self._jwks_async_lock: Any = None
        self._jwks_sync_lock = threading.Lock()
        if self.config.decision_cache_enabled:
            self._decision_cache = TTLCache(
                maxsize=self.config.decision_cache_max_entries,
                ttl=self.config.decision_cache_ttl_seconds,
            )

    # ------------------------------------------------------------------
    # Internal HTTP helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.config.vault_api_key:
            headers["X-Vault-API-Key"] = self.config.vault_api_key
        return headers

    def _request_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = self._headers()
        if extra:
            headers.update(extra)
        return inject_otel_headers(headers, self.config.otel_enabled)

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
        retryable HTTP status codes (5xx). 429 responses honor the
        ``Retry-After`` header (Vault backpressure §2.1) and do NOT consume
        the ``max_retries`` budget — they're cooperative backoff, not
        transport failures. After ``MAX_CONSECUTIVE_429`` waves with no
        success the SDK gives up with ``QueueSaturatedError``.

        Raises ``VaultConnectionError`` after all transport attempts are
        exhausted.
        """
        attempt = 0
        consecutive_429 = 0
        last_retry_after: float | None = None
        while True:
            try:
                response = fn()
            except httpx.TransportError as exc:
                if attempt < self.config.max_retries:
                    time.sleep(self._backoff_delay(attempt))
                    attempt += 1
                    continue
                raise VaultConnectionError(str(exc)) from exc

            if response.status_code == 429:
                # Treat 429 as cooperative backoff: don't consume the retry
                # budget, sleep for the server-requested duration (or fall
                # back to jitter if no header). Bound the loop separately.
                consecutive_429 += 1
                if consecutive_429 > MAX_CONSECUTIVE_429:
                    raise QueueSaturatedError(consecutive_429 - 1, last_retry_after)
                retry_after = _parse_retry_after(response.headers.get("Retry-After"))
                if retry_after is not None:
                    last_retry_after = retry_after
                    time.sleep(retry_after)
                else:
                    time.sleep(self._backoff_delay(attempt))
                continue

            # Reset 429 streak on any non-429 response — a single success in
            # between resets the SDK's "is the queue dying?" signal.
            consecutive_429 = 0

            if response.status_code in _RETRYABLE_STATUS_CODES and attempt < self.config.max_retries:
                time.sleep(self._backoff_delay(attempt))
                attempt += 1
                continue
            return response

    async def _async_retry(self, fn: Callable[[], Awaitable[httpx.Response]]) -> httpx.Response:
        """Async variant of ``_sync_retry``. Same semantics."""
        import asyncio

        attempt = 0
        consecutive_429 = 0
        last_retry_after: float | None = None
        while True:
            try:
                response = await fn()
            except httpx.TransportError as exc:
                if attempt < self.config.max_retries:
                    await asyncio.sleep(self._backoff_delay(attempt))
                    attempt += 1
                    continue
                raise VaultConnectionError(str(exc)) from exc

            if response.status_code == 429:
                consecutive_429 += 1
                if consecutive_429 > MAX_CONSECUTIVE_429:
                    raise QueueSaturatedError(consecutive_429 - 1, last_retry_after)
                retry_after = _parse_retry_after(response.headers.get("Retry-After"))
                if retry_after is not None:
                    last_retry_after = retry_after
                    await asyncio.sleep(retry_after)
                else:
                    await asyncio.sleep(self._backoff_delay(attempt))
                continue

            consecutive_429 = 0

            if response.status_code in _RETRYABLE_STATUS_CODES and attempt < self.config.max_retries:
                await asyncio.sleep(self._backoff_delay(attempt))
                attempt += 1
                continue
            return response

    # ------------------------------------------------------------------
    # Decision cache helpers
    # ------------------------------------------------------------------

    def _enrich_request(self, request: ClearanceRequest) -> ClearanceRequest:
        """Return request with human_principal, parent_jti, and counterparty
        destination_* fields filled in from config/instance defaults / hints.
        Caller-supplied destination_* always wins over the inferred values."""
        updates: dict[str, Any] = {}
        if request.human_principal is None and self.config.principal_id:
            updates["human_principal"] = self.config.principal_id
        if request.parent_jti is None and self._parent_jti:
            updates["parent_jti"] = self._parent_jti
        if (
            request.destination_uri is None
            or request.destination_provider is None
            or request.destination_account_ref is None
        ):
            from .counterparty import extract as _extract_counterparty

            inferred = _extract_counterparty(request.tool_name, request.tool_args)
            if request.destination_uri is None and "destination_uri" in inferred:
                updates["destination_uri"] = inferred["destination_uri"]
            if request.destination_provider is None and "destination_provider" in inferred:
                updates["destination_provider"] = inferred["destination_provider"]
            if request.destination_account_ref is None and "destination_account_ref" in inferred:
                updates["destination_account_ref"] = inferred["destination_account_ref"]
        return request.model_copy(update=updates) if updates else request

    def _enrich_request_with_telemetry(self, request: ClearanceRequest) -> ClearanceRequest:
        otel = current_otel_metadata(self.config.otel_enabled)
        if not otel:
            return request
        context = dict(request.context or {})
        telemetry = dict(context.get("telemetry") or {})
        telemetry["otel"] = otel
        context["telemetry"] = telemetry
        return request.model_copy(update={"context": context})

    def create_delegated_client(self, parent_jti: str) -> "BylawClient":
        """Return a new client that auto-injects *parent_jti* on every clearance request.

        The returned client shares the same ``VaultConfig`` but does not share
        HTTP connections or the decision cache, so it is safe to use concurrently.
        """
        return BylawClient(config=self.config, _parent_jti=parent_jti)

    def _build_cache_key(self, request: ClearanceRequest) -> str:
        """Return a stable hex cache key for a clearance request, or '' if not cacheable."""
        try:
            canonical_args = json.dumps(
                request.tool_args or {},
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
        except Exception:
            return ""
        if len(canonical_args) > 65_536:
            return ""
        agent_id = request.agent_id or self.config.agent_id or ""
        policy_id = (request.context or {}).get("policy_id") or ""
        material = f"{agent_id}\x00{request.tool_name}\x00{canonical_args}\x00{policy_id}"
        return hashlib.sha256(material.encode()).hexdigest()

    def _cache_get(self, key: str) -> dict[str, Any] | None:
        if self._decision_cache is None or not key:
            return None
        with self._decision_cache_lock:
            return self._decision_cache.get(key)

    def _cache_put(self, key: str, envelope: dict[str, Any]) -> None:
        if self._decision_cache is None or not key:
            return
        with self._decision_cache_lock:
            self._decision_cache[key] = envelope

    def clear_cache(self) -> None:
        """Flush all cached decision envelopes."""
        if self._decision_cache is None:
            return
        with self._decision_cache_lock:
            self._decision_cache.clear()

    @staticmethod
    def _is_cacheable(clearance: ClearanceResponse) -> bool:
        return (
            clearance.decision_status == "approved"
            and clearance.status == "approved"
            and bool(clearance.policy_version_id)
            and clearance.token is not None
        )

    def _make_envelope(self, clearance: ClearanceResponse) -> dict[str, Any]:
        return {
            "decision_status": clearance.decision_status,
            "reason": clearance.reason,
            "policy_version_id": clearance.policy_version_id or "",
            "policy_content_hash": clearance.policy_content_hash or "",
            "confidence_bucket": clearance.confidence_bucket,
            "minimum_confidence_bucket": clearance.minimum_confidence_bucket,
            "original_request_id": clearance.request_id,
        }

    def _mint_token(self, request: ClearanceRequest, envelope: dict[str, Any]) -> ClearanceResponse:
        """Call /mint-token to get a fresh A-JWT from a cached decision envelope (sync)."""
        mint_body = {
            "tool_name": request.tool_name,
            "tool_args": request.tool_args or {},
            "agent_id": request.agent_id or self.config.agent_id or "",
            "session_id": request.session_id or self.config.session_id or "",
            "policy_id": (request.context or {}).get("policy_id") or "",
            "policy_version_id": envelope["policy_version_id"],
            "policy_content_hash": envelope["policy_content_hash"],
            "original_request_id": envelope["original_request_id"],
            "confidence_bucket": envelope["confidence_bucket"],
            "reason": envelope["reason"],
            "human_principal": request.human_principal or self.config.principal_id,
            "destination_uri": request.destination_uri or "",
            "destination_provider": request.destination_provider or "",
            "destination_account_ref": request.destination_account_ref or "",
            "data_categories": request.data_categories or [],
            "purpose": request.purpose or "",
            "processing_register_ref": request.processing_register_ref or "",
            "dataset_ref": request.dataset_ref or "",
        }
        idem_headers = {"Idempotency-Key": str(uuid.uuid4())}
        try:
            response = self._sync_retry(
                lambda: self._get_sync_client().post("/mint-token", json=mint_body, headers=idem_headers)
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise VaultConnectionError(
                f"Vault /mint-token returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc
        data = response.json()
        return ClearanceResponse(
            status="approved",
            decision_status="approved",
            requires_manual_review=False,
            token=data.get("token"),
            reason=data.get("reason", envelope["reason"]),
            request_id=data.get("request_id", ""),
            confidence_bucket=envelope["confidence_bucket"],
            minimum_confidence_bucket=envelope.get("minimum_confidence_bucket", "high"),
            policy_version_id=envelope["policy_version_id"],
            policy_content_hash=envelope["policy_content_hash"],
        )

    async def _amint_token(self, request: ClearanceRequest, envelope: dict[str, Any]) -> ClearanceResponse:
        """Call /mint-token to get a fresh A-JWT from a cached decision envelope (async)."""
        mint_body = {
            "tool_name": request.tool_name,
            "tool_args": request.tool_args or {},
            "agent_id": request.agent_id or self.config.agent_id or "",
            "session_id": request.session_id or self.config.session_id or "",
            "policy_id": (request.context or {}).get("policy_id") or "",
            "policy_version_id": envelope["policy_version_id"],
            "policy_content_hash": envelope["policy_content_hash"],
            "original_request_id": envelope["original_request_id"],
            "confidence_bucket": envelope["confidence_bucket"],
            "reason": envelope["reason"],
            "human_principal": request.human_principal or self.config.principal_id,
            "destination_uri": request.destination_uri or "",
            "destination_provider": request.destination_provider or "",
            "destination_account_ref": request.destination_account_ref or "",
            "data_categories": request.data_categories or [],
            "purpose": request.purpose or "",
            "processing_register_ref": request.processing_register_ref or "",
            "dataset_ref": request.dataset_ref or "",
        }
        idem_headers = {"Idempotency-Key": str(uuid.uuid4())}
        try:
            response = await self._async_retry(
                lambda: self._get_async_client().post("/mint-token", json=mint_body, headers=idem_headers)
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise VaultConnectionError(
                f"Vault /mint-token returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc
        data = response.json()
        return ClearanceResponse(
            status="approved",
            decision_status="approved",
            requires_manual_review=False,
            token=data.get("token"),
            reason=data.get("reason", envelope["reason"]),
            request_id=data.get("request_id", ""),
            confidence_bucket=envelope["confidence_bucket"],
            minimum_confidence_bucket=envelope.get("minimum_confidence_bucket", "high"),
            policy_version_id=envelope["policy_version_id"],
            policy_content_hash=envelope["policy_content_hash"],
        )

    # ------------------------------------------------------------------
    # Clearance — sync
    # ------------------------------------------------------------------

    def request_clearance(self, request: ClearanceRequest) -> ClearanceResponse:
        """Send a clearance request to the Vault (sync).

        When the decision cache is enabled (``decision_cache_enabled=True`` in
        ``VaultConfig``), an approved response is memoized.  Subsequent identical
        calls skip the LLM judge and call ``/mint-token`` for a fresh A-JWT.

        Raises:
            ClearanceDeniedError: If the Vault denies the request.
            VaultConnectionError: If the Vault is unreachable.
        """
        request = self._enrich_request(request)
        request = self._enrich_request_with_telemetry(request)
        cache_key = self._build_cache_key(request)
        envelope = self._cache_get(cache_key)
        if envelope is not None:
            clearance = self._mint_token(request, envelope)
            record_clearance_event(self.config.otel_enabled, "ledgix.clearance.decision", request, clearance)
            if self.config.verify_jwt and clearance.token:
                self.verify_token(clearance.token)
            return clearance

        idem_headers = self._request_headers({"Idempotency-Key": str(uuid.uuid4())})
        try:
            response = self._sync_retry(
                lambda: self._get_sync_client().post(
                    "/request-clearance",
                    content=request.model_dump_json(),
                    headers=idem_headers,
                )
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise VaultConnectionError(
                f"Vault returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc

        clearance = ClearanceResponse.model_validate(response.json())
        if clearance.status in {"pending_review", "pendingReview", "processing"}:
            record_clearance_event(self.config.otel_enabled, "ledgix.clearance.pending_review", request, clearance)
        result = self._resolve_pending_clearance(clearance)
        if isinstance(result, PendingApproval):
            raise ReviewPendingError(result)
        clearance = result

        record_clearance_event(self.config.otel_enabled, "ledgix.clearance.decision", request, clearance)
        if not clearance.is_approved:
            raise ClearanceDeniedError(
                reason=clearance.reason,
                request_id=clearance.request_id,
            )

        if self.config.verify_jwt and clearance.token:
            self.verify_token(clearance.token)

        if self._is_cacheable(clearance):
            self._cache_put(cache_key, self._make_envelope(clearance))

        return clearance

    # ------------------------------------------------------------------
    # Clearance — async
    # ------------------------------------------------------------------

    async def arequest_clearance(self, request: ClearanceRequest) -> ClearanceResponse:
        """Send a clearance request to the Vault (async).

        When the decision cache is enabled (``decision_cache_enabled=True`` in
        ``VaultConfig``), an approved response is memoized.  Subsequent identical
        calls skip the LLM judge and call ``/mint-token`` for a fresh A-JWT.

        Raises:
            ClearanceDeniedError: If the Vault denies the request.
            VaultConnectionError: If the Vault is unreachable.
        """
        request = self._enrich_request(request)
        request = self._enrich_request_with_telemetry(request)
        cache_key = self._build_cache_key(request)
        envelope = self._cache_get(cache_key)
        if envelope is not None:
            clearance = await self._amint_token(request, envelope)
            record_clearance_event(self.config.otel_enabled, "ledgix.clearance.decision", request, clearance)
            if self.config.verify_jwt and clearance.token:
                await self.averify_token(clearance.token)
            return clearance

        idem_headers = self._request_headers({"Idempotency-Key": str(uuid.uuid4())})
        try:
            response = await self._async_retry(
                lambda: self._get_async_client().post(
                    "/request-clearance",
                    content=request.model_dump_json(),
                    headers=idem_headers,
                )
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise VaultConnectionError(
                f"Vault returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc

        clearance = ClearanceResponse.model_validate(response.json())
        if clearance.status in {"pending_review", "pendingReview", "processing"}:
            record_clearance_event(self.config.otel_enabled, "ledgix.clearance.pending_review", request, clearance)
        result = await self._aresolve_pending_clearance(clearance)
        if isinstance(result, PendingApproval):
            raise ReviewPendingError(result)
        clearance = result

        record_clearance_event(self.config.otel_enabled, "ledgix.clearance.decision", request, clearance)
        if not clearance.is_approved:
            raise ClearanceDeniedError(
                reason=clearance.reason,
                request_id=clearance.request_id,
            )

        if self.config.verify_jwt and clearance.token:
            await self.averify_token(clearance.token)

        if self._is_cacheable(clearance):
            self._cache_put(cache_key, self._make_envelope(clearance))

        return clearance

    # ------------------------------------------------------------------
    # Policy registration
    # ------------------------------------------------------------------

    def register_policy(self, policy: PolicyRegistration) -> PolicyRegistrationResponse:
        """Register a policy with the Vault (sync)."""
        idem_headers = {"Idempotency-Key": str(uuid.uuid4())}
        try:
            response = self._sync_retry(
                lambda: self._get_sync_client().post(
                    "/register-policy",
                    content=policy.model_dump_json(),
                    headers=idem_headers,
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
        idem_headers = {"Idempotency-Key": str(uuid.uuid4())}
        try:
            response = await self._async_retry(
                lambda: self._get_async_client().post(
                    "/register-policy",
                    content=policy.model_dump_json(),
                    headers=idem_headers,
                )
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise PolicyRegistrationError(
                f"Vault returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc

        return PolicyRegistrationResponse.model_validate(response.json())

    # ------------------------------------------------------------------
    # Evidence runtime (Phase 2)
    # ------------------------------------------------------------------

    def register_fact(self, request: RegisterFactRequest) -> RegisteredFact:
        """Register an evidence fact extracted from a source tool result (sync)."""
        idem_headers = {"Idempotency-Key": str(uuid.uuid4())}
        try:
            response = self._sync_retry(
                lambda: self._get_sync_client().post(
                    "/v1/evidence/facts", content=request.model_dump_json(), headers=idem_headers
                )
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise EvidenceError(
                f"Vault returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc
        payload = response.json()
        return RegisteredFact.model_validate(payload.get("fact", payload))

    async def aregister_fact(self, request: RegisterFactRequest) -> RegisteredFact:
        """Register an evidence fact (async)."""
        idem_headers = {"Idempotency-Key": str(uuid.uuid4())}
        try:
            response = await self._async_retry(
                lambda: self._get_async_client().post(
                    "/v1/evidence/facts", content=request.model_dump_json(), headers=idem_headers
                )
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise EvidenceError(
                f"Vault returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc
        payload = response.json()
        return RegisteredFact.model_validate(payload.get("fact", payload))

    def check_action(self, request: CheckActionRequest) -> CheckActionResult:
        """Evaluate a protected action against current evidence (sync)."""
        try:
            response = self._sync_retry(
                lambda: self._get_sync_client().post(
                    "/v1/evidence/check-action", content=request.model_dump_json()
                )
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise EvidenceError(
                f"Vault returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc
        return CheckActionResult.model_validate(response.json())

    async def acheck_action(self, request: CheckActionRequest) -> CheckActionResult:
        """Evaluate a protected action against current evidence (async)."""
        try:
            response = await self._async_retry(
                lambda: self._get_async_client().post(
                    "/v1/evidence/check-action", content=request.model_dump_json()
                )
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise EvidenceError(
                f"Vault returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc
        return CheckActionResult.model_validate(response.json())

    def check_output(self, request: CheckOutputRequest) -> CheckActionResult:
        """Verify the numbers in a customer-facing response are grounded (sync)."""
        try:
            response = self._sync_retry(
                lambda: self._get_sync_client().post(
                    "/v1/evidence/check-output", content=request.model_dump_json()
                )
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise EvidenceError(
                f"Vault returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc
        return CheckActionResult.model_validate(response.json())

    async def acheck_output(self, request: CheckOutputRequest) -> CheckActionResult:
        """Verify the numbers in a customer-facing response are grounded (async)."""
        try:
            response = await self._async_retry(
                lambda: self._get_async_client().post(
                    "/v1/evidence/check-output", content=request.model_dump_json()
                )
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise EvidenceError(
                f"Vault returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc
        return CheckActionResult.model_validate(response.json())

    def fetch_challenge(self, challenge_id: str) -> Challenge:
        """Fetch a host-native challenge to render (sync)."""
        try:
            response = self._sync_retry(
                lambda: self._get_sync_client().get(f"/v1/evidence/challenges/{challenge_id}")
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise EvidenceError(
                f"Vault returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc
        return Challenge.model_validate(response.json())

    async def afetch_challenge(self, challenge_id: str) -> Challenge:
        """Fetch a host-native challenge to render (async)."""
        try:
            response = await self._async_retry(
                lambda: self._get_async_client().get(f"/v1/evidence/challenges/{challenge_id}")
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise EvidenceError(
                f"Vault returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc
        return Challenge.model_validate(response.json())

    def resolve_challenge(self, request: ResolveChallengeRequest) -> CheckActionResult:
        """Post a trusted decision event to resolve a challenge (sync)."""
        try:
            response = self._sync_retry(
                lambda: self._get_sync_client().post(
                    "/v1/evidence/resolve-challenge", content=request.model_dump_json()
                )
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise EvidenceError(
                f"Vault returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc
        return CheckActionResult.model_validate(response.json())

    async def aresolve_challenge(self, request: ResolveChallengeRequest) -> CheckActionResult:
        """Post a trusted decision event to resolve a challenge (async)."""
        try:
            response = await self._async_retry(
                lambda: self._get_async_client().post(
                    "/v1/evidence/resolve-challenge", content=request.model_dump_json()
                )
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise EvidenceError(
                f"Vault returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc
        return CheckActionResult.model_validate(response.json())

    def fetch_evidence_graph(
        self, customer_id: str, session_id: str = ""
    ) -> EvidenceGraph:
        """Fetch the current Evidence Graph for a customer/session (sync)."""
        params = {"customer_id": customer_id}
        if session_id:
            params["session_id"] = session_id
        try:
            response = self._sync_retry(
                lambda: self._get_sync_client().get("/v1/evidence/graph", params=params)
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise EvidenceError(
                f"Vault returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc
        return EvidenceGraph.model_validate(response.json())

    async def afetch_evidence_graph(
        self, customer_id: str, session_id: str = ""
    ) -> EvidenceGraph:
        """Fetch the current Evidence Graph for a customer/session (async)."""
        params = {"customer_id": customer_id}
        if session_id:
            params["session_id"] = session_id
        try:
            response = await self._async_retry(
                lambda: self._get_async_client().get("/v1/evidence/graph", params=params)
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise EvidenceError(
                f"Vault returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc
        return EvidenceGraph.model_validate(response.json())

    # ------------------------------------------------------------------
    # JWKS + A-JWT verification
    # ------------------------------------------------------------------

    def _resolve_pending_clearance(
        self, clearance: ClearanceResponse
    ) -> ClearanceResponse | PendingApproval:
        if clearance.status not in {"processing", "pending_review"}:
            return clearance

        if self.config.review_mode == "detach":
            return PendingApproval(clearance.request_id, self, clearance)

        deadline = time.monotonic() + self.config.review_timeout
        while time.monotonic() < deadline:
            time.sleep(self.config.review_poll_interval)
            response = self._get_sync_client().get(f"/clearance-status/{clearance.request_id}")
            response.raise_for_status()
            clearance = ClearanceResponse.model_validate(response.json())
            if clearance.status not in {"processing", "pending_review"}:
                return clearance
        raise ManualReviewTimeoutError(clearance.request_id)

    async def _aresolve_pending_clearance(
        self, clearance: ClearanceResponse
    ) -> ClearanceResponse | PendingApproval:
        if clearance.status not in {"processing", "pending_review"}:
            return clearance

        if self.config.review_mode == "detach":
            return PendingApproval(clearance.request_id, self, clearance)

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
        """Fetch the Vault's JWKS (JSON Web Key Set) for token verification (sync).

        Serialized with a threading.Lock + double-check so concurrent threads
        verifying tokens only trigger one network round-trip.
        """
        start_fetched_at = self._jwks_fetched_at
        with self._jwks_sync_lock:
            if self._jwks_fetched_at > start_fetched_at and self._jwks_cache is not None:
                return self._jwks_cache
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
            self._index_jwks_by_kid(self._jwks_cache)
            return self._jwks_cache

    async def afetch_jwks(self) -> dict[str, Any]:
        """Fetch the Vault's JWKS for token verification (async).

        Protected by an asyncio.Lock + double-check on _jwks_fetched_at so a
        thundering herd of concurrent verify_token() callers only triggers one
        network round-trip.
        """
        import asyncio

        if self._jwks_async_lock is None:
            self._jwks_async_lock = asyncio.Lock()
        start_fetched_at = self._jwks_fetched_at
        async with self._jwks_async_lock:
            # Double-check: another coroutine may have refetched while we waited.
            if self._jwks_fetched_at > start_fetched_at and self._jwks_cache is not None:
                return self._jwks_cache
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
            self._index_jwks_by_kid(self._jwks_cache)
            return self._jwks_cache

    def _index_jwks_by_kid(self, jwks: dict[str, Any]) -> None:
        """Rebuild the kid→JWK index from the raw JWKS response."""
        keys_by_kid: dict[str, Any] = {}
        for key in jwks.get("keys", []):
            kid = key.get("kid")
            if kid:
                keys_by_kid[kid] = key
        # Also expose all keys under a sentinel so kid-less tokens can still
        # fall back to the first key (legacy; Vault always sets kid today).
        if not keys_by_kid and jwks.get("keys"):
            keys_by_kid["__default__"] = jwks["keys"][0]
        self._jwks_keys_by_kid = keys_by_kid
        self._jwks_fetched_at = time.monotonic()

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
            ReplayDetectedError: If this jti has already been consumed.
        """
        kid = self._peek_token_kid(token)
        if self._jwks_cache is None or not self._has_key(kid):
            self.fetch_jwks()
        return self._decode_token(token)

    async def averify_token(self, token: str) -> dict[str, Any]:
        """Verify an A-JWT using the Vault's public key (async).

        Raises:
            TokenVerificationError: If the token is invalid, expired, or
                the JWKS cannot be fetched.
            ReplayDetectedError: If this jti has already been consumed.
        """
        kid = self._peek_token_kid(token)
        if self._jwks_cache is None or not self._has_key(kid):
            await self.afetch_jwks()
        return self._decode_token(token)

    def _peek_token_kid(self, token: str) -> str | None:
        """Return the kid header of a token without verifying its signature."""
        try:
            header = jwt.get_unverified_header(token)
            return header.get("kid")
        except jwt.exceptions.DecodeError:
            return None

    def _has_key(self, kid: str | None) -> bool:
        """Return True if the given kid is indexed in the current JWKS cache."""
        if not self._jwks_keys_by_kid:
            return False
        if kid:
            return kid in self._jwks_keys_by_kid
        return "__default__" in self._jwks_keys_by_kid

    def _decode_token(self, token: str) -> dict[str, Any]:
        """Verify an A-JWT against the cached JWKS and check jti replay.

        Security invariants enforced here:
        - Kid matching: the token's `kid` header selects an explicit JWK from the
          JWKS; unknown kids are rejected fail-closed (no wildcard fallback).
        - Algorithm pinned to EdDSA — RS256/HS256 confusion attacks are impossible.
        - jti replay: every jti is tracked in a TTL cache for max_token_lifetime_seconds.
          A missing or re-presented jti raises ReplayDetectedError immediately.

        JWKS must already be populated before calling this method.
        Raises TokenVerificationError on signature / claim failures.
        Raises ReplayDetectedError if the jti has already been consumed.
        """
        if not self._jwks_cache:
            raise TokenVerificationError("No JWKS available from Vault")
        if not self._jwks_keys_by_kid:
            raise TokenVerificationError("JWKS contains no keys")

        try:
            kid = self._peek_token_kid(token)
            # Select the key: prefer exact kid match, fall back to __default__ for
            # kid-less tokens (legacy), fail-closed otherwise.
            key_data = self._jwks_keys_by_kid.get(kid) if kid else None
            if key_data is None:
                key_data = self._jwks_keys_by_kid.get("__default__")
            if key_data is None:
                raise TokenVerificationError(
                    f"A-JWT kid={kid!r} not found in JWKS — key may have rotated; "
                    "refetch JWKS or upgrade Vault"
                )

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

        except TokenVerificationError:
            raise
        except jwt.ExpiredSignatureError as exc:
            raise TokenVerificationError("A-JWT has expired") from exc
        except jwt.InvalidTokenError as exc:
            raise TokenVerificationError(f"Invalid A-JWT: {exc}") from exc

        # jti replay detection — fail-closed: a missing jti is rejected.
        jti = decoded.get("jti")
        if not jti:
            raise TokenVerificationError("A-JWT missing jti claim")
        with self._seen_jtis_lock:
            if jti in self._seen_jtis:
                raise ReplayDetectedError(jti)
            # cachetools.TTLCache evicts on access; inserting with a dummy value
            # records the jti for max_token_lifetime_seconds.
            self._seen_jtis[jti] = True

        return decoded

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

            if self._has_protected_event_fields(bundle.event):
                expected_event_hash = self._build_event_hash(bundle.event)
                if expected_event_hash != bundle.event.event_hash:
                    raise TokenVerificationError("Ledger event hash mismatch in proof bundle")
            expected_leaf_hash = self._hash_leaf(bundle.event.event_hash)
            if expected_leaf_hash != bundle.event.leaf_hash:
                raise TokenVerificationError("Ledger leaf hash mismatch in proof bundle")
            if bundle.event.receipt_algorithm != "Ed25519":
                raise TokenVerificationError(
                    f"Unsupported ledger receipt algorithm {bundle.event.receipt_algorithm}"
                )
            if (
                not bundle.event.receipt_payload
                or not bundle.event.receipt_signature
                or not bundle.event.receipt_key_id
            ):
                raise TokenVerificationError("Missing receipt proof data in proof bundle")
            payload_bytes = self._decode_base64url(bundle.event.receipt_payload)
            rebuilt_payload = self._build_receipt_payload(bundle.event)
            if payload_bytes != rebuilt_payload:
                raise TokenVerificationError("Ledger receipt payload mismatch in proof bundle")
            key_for_kid(bundle.event.receipt_key_id).verify(
                self._decode_base64url(bundle.event.receipt_signature),
                payload_bytes,
            )

            checkpoints = [bundle.inclusion.checkpoint]
            if bundle.consistency:
                if (
                    bundle.consistency.from_checkpoint.checkpoint_hash
                    != bundle.inclusion.checkpoint.checkpoint_hash
                ):
                    raise TokenVerificationError(
                        "Ledger consistency proof does not match the inclusion checkpoint"
                    )
                checkpoints.append(bundle.consistency.to_checkpoint)

            for checkpoint in checkpoints:
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
                checkpoint_payload = self._decode_base64url(checkpoint.checkpoint_payload)
                rebuilt_checkpoint_payload = self._build_checkpoint_payload(checkpoint)
                if checkpoint_payload != rebuilt_checkpoint_payload:
                    raise TokenVerificationError("Ledger checkpoint payload mismatch in proof bundle")
                if self._hash_checkpoint_payload(checkpoint_payload) != checkpoint.checkpoint_hash:
                    raise TokenVerificationError("Ledger checkpoint hash mismatch in proof bundle")
                key_for_kid(checkpoint.signer_key_id).verify(
                    self._decode_base64url(checkpoint.checkpoint_signature),
                    checkpoint_payload,
                )

            if not self._verify_inclusion_proof(
                bundle.event.leaf_hash,
                bundle.inclusion.leaf_index,
                bundle.inclusion.tree_size,
                bundle.inclusion.path,
                bundle.inclusion.checkpoint.root_hash,
            ):
                raise TokenVerificationError("Ledger inclusion proof is invalid")
            if bundle.consistency and not self._verify_consistency_proof(
                bundle.consistency.from_checkpoint.tree_size,
                bundle.consistency.to_checkpoint.tree_size,
                bundle.consistency.from_checkpoint.root_hash,
                bundle.consistency.to_checkpoint.root_hash,
                bundle.consistency.path,
            ):
                raise TokenVerificationError("Ledger consistency proof is invalid")

            latest_checkpoint_hash = (
                bundle.consistency.to_checkpoint.checkpoint_hash
                if bundle.consistency
                else bundle.inclusion.checkpoint.checkpoint_hash
            )
            return LedgerVerificationResult(
                intact=True,
                verified_entries=1,
                verified_checkpoints=2 if bundle.consistency else 1,
                verified_manifests=2 if bundle.consistency else 1,
                latest_leaf_hash=bundle.event.leaf_hash,
                latest_checkpoint_hash=latest_checkpoint_hash,
                latest_manifest_hash=latest_checkpoint_hash,
                coverage_note=None,
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
        raw_tool_args = entry.raw_tool_args if entry.raw_tool_args is not _MISSING else entry.tool_args
        raw_action_metadata = (
            entry.raw_action_metadata if entry.raw_action_metadata is not _MISSING else entry.action_metadata
        )
        if raw_action_metadata is _MISSING:
            raw_action_metadata = {}
        raw_citations = entry.raw_citations if entry.raw_citations is not _MISSING else entry.citations
        raw_evidence_chunks = (
            entry.raw_evidence_chunks if entry.raw_evidence_chunks is not _MISSING else entry.evidence_chunks
        )

        payload = self._encode_deterministic_cbor(
            {
                "accepted_at": entry.accepted_at,
                "action_category": entry.action_category,
                "action_metadata": self._normalize_json_numbers_for_cbor(raw_action_metadata),
                "agent_id": entry.agent_id,
                "approved": entry.approved,
                "canonical_version": entry.canonical_version,
                "citations": self._normalize_json_numbers_for_cbor(raw_citations),
                "confidence": entry.confidence,
                "event_uuid": entry.event_uuid,
                "evidence_chunks": self._normalize_json_numbers_for_cbor(raw_evidence_chunks),
                "intent_hash": entry.intent_hash,
                "policy_id": entry.policy_id,
                "policy_version_id": entry.policy_version_id,
                "policy_content_hash": entry.policy_content_hash,
                "reason": entry.reason,
                "request_id": entry.request_id,
                "tool_args": self._normalize_json_numbers_for_cbor(raw_tool_args),
                "tool_name": entry.tool_name,
            }
        )
        current_hash = self._hash_event_payload(payload)
        if current_hash == entry.event_hash:
            return current_hash

        legacy_payload = self._encode_deterministic_cbor(
            {
                "accepted_at": entry.accepted_at,
                "agent_id": entry.agent_id,
                "approved": entry.approved,
                "canonical_version": entry.canonical_version,
                "citations": self._normalize_json_numbers_for_cbor(raw_citations),
                "confidence": entry.confidence,
                "event_uuid": entry.event_uuid,
                "evidence_chunks": self._normalize_json_numbers_for_cbor(raw_evidence_chunks),
                "intent_hash": entry.intent_hash,
                "policy_id": entry.policy_id,
                "reason": entry.reason,
                "request_id": entry.request_id,
                "tool_args": self._normalize_json_numbers_for_cbor(raw_tool_args),
                "tool_name": entry.tool_name,
            }
        )
        return self._hash_event_payload(legacy_payload)

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

    def __enter__(self) -> BylawClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    async def __aenter__(self) -> BylawClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()
