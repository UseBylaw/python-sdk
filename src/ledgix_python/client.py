# Ledgix ALCV — Client
# Sync + async HTTP client for Vault communication and A-JWT verification

from __future__ import annotations

import json
import time
from typing import Any

import httpx
import jwt

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
    # Clearance — sync
    # ------------------------------------------------------------------

    def request_clearance(self, request: ClearanceRequest) -> ClearanceResponse:
        """Send a clearance request to the Vault (sync).

        Raises:
            ClearanceDeniedError: If the Vault denies the request.
            VaultConnectionError: If the Vault is unreachable.
        """
        try:
            response = self._get_sync_client().post(
                "/request-clearance",
                content=request.model_dump_json(),
            )
            response.raise_for_status()
        except httpx.ConnectError as exc:
            raise VaultConnectionError(str(exc)) from exc
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
            response = await self._get_async_client().post(
                "/request-clearance",
                content=request.model_dump_json(),
            )
            response.raise_for_status()
        except httpx.ConnectError as exc:
            raise VaultConnectionError(str(exc)) from exc
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
            response = self._get_sync_client().post(
                "/register-policy",
                content=policy.model_dump_json(),
            )
            response.raise_for_status()
        except httpx.ConnectError as exc:
            raise VaultConnectionError(str(exc)) from exc
        except httpx.HTTPStatusError as exc:
            raise PolicyRegistrationError(
                f"Vault returned HTTP {exc.response.status_code}: {exc.response.text}"
            ) from exc

        return PolicyRegistrationResponse.model_validate(response.json())

    async def aregister_policy(self, policy: PolicyRegistration) -> PolicyRegistrationResponse:
        """Register a policy with the Vault (async)."""
        try:
            response = await self._get_async_client().post(
                "/register-policy",
                content=policy.model_dump_json(),
            )
            response.raise_for_status()
        except httpx.ConnectError as exc:
            raise VaultConnectionError(str(exc)) from exc
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
            response = self._get_sync_client().get("/.well-known/jwks.json")
            response.raise_for_status()
        except httpx.ConnectError as exc:
            raise VaultConnectionError(str(exc)) from exc
        except httpx.HTTPStatusError as exc:
            raise VaultConnectionError(
                f"Failed to fetch JWKS: HTTP {exc.response.status_code}"
            ) from exc

        self._jwks_cache = response.json()
        return self._jwks_cache

    async def afetch_jwks(self) -> dict[str, Any]:
        """Fetch the Vault's JWKS for token verification (async)."""
        try:
            response = await self._get_async_client().get("/.well-known/jwks.json")
            response.raise_for_status()
        except httpx.ConnectError as exc:
            raise VaultConnectionError(str(exc)) from exc
        except httpx.HTTPStatusError as exc:
            raise VaultConnectionError(
                f"Failed to fetch JWKS: HTTP {exc.response.status_code}"
            ) from exc

        self._jwks_cache = response.json()
        return self._jwks_cache

    def verify_token(self, token: str) -> dict[str, Any]:
        """Verify an A-JWT using the Vault's public key (sync).

        Returns the decoded token payload on success.

        Raises:
            TokenVerificationError: If the token is invalid, expired, or
                the JWKS cannot be fetched.
        """
        return self._verify_token_internal(token, sync=True)

    async def averify_token(self, token: str) -> dict[str, Any]:
        """Verify an A-JWT using the Vault's public key (async)."""
        return self._verify_token_internal(token, sync=False)

    def _verify_token_internal(self, token: str, sync: bool = True) -> dict[str, Any]:
        """Shared verification logic.

        Note: For async callers this is still synchronous internally
        because PyJWT is sync. The async variant pre-fetches JWKS
        asynchronously before calling this.
        """
        if self._jwks_cache is None:
            if sync:
                self.fetch_jwks()
            else:
                # In async context, caller must have pre-fetched JWKS.
                # Fall back to sync fetch if cache is empty.
                self.fetch_jwks()

        if not self._jwks_cache:
            raise TokenVerificationError("No JWKS available from Vault")

        try:
            # Extract the first key from the JWKS
            jwks = self._jwks_cache
            if "keys" not in jwks or not jwks["keys"]:
                raise TokenVerificationError("JWKS contains no keys")

            # Build a PyJWT key from the JWK
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

        except jwt.ExpiredSignatureError as exc:
            raise TokenVerificationError("A-JWT has expired") from exc
        except jwt.InvalidTokenError as exc:
            raise TokenVerificationError(f"Invalid A-JWT: {exc}") from exc
        except Exception as exc:
            raise TokenVerificationError(f"Token verification failed: {exc}") from exc

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
