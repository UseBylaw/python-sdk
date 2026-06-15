# Ledgix ALCV — Configuration
# Environment-driven configuration via pydantic-settings

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class VaultConfig(BaseSettings):
    """Configuration for connecting to the ALCV Vault.

    Values are loaded from environment variables prefixed with ``LEDGIX_``,
    e.g. ``LEDGIX_VAULT_URL``, or can be passed directly to the constructor.
    """

    model_config = SettingsConfigDict(
        env_prefix="LEDGIX_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    vault_url: str = "http://localhost:8000"
    """Base URL of the ALCV Vault server."""

    vault_api_key: str = ""
    """API key sent as ``X-Vault-API-Key`` header for Shim→Vault auth."""

    vault_timeout: float = 30.0
    """HTTP request timeout in seconds."""

    verify_jwt: bool = True
    """Whether to verify A-JWTs returned by the Vault using its JWKS endpoint."""

    jwt_issuer: str = "alcv-vault"
    """Expected issuer for Vault A-JWTs."""

    jwt_audience: str = "ledgix-sdk"
    """Expected audience for Vault A-JWTs."""

    agent_id: str = "default-agent"
    """Identifier for the agent using this SDK instance."""

    session_id: str = ""
    """Optional session identifier for grouping related clearance requests."""

    review_poll_interval: float = 2.0
    """Polling interval in seconds while waiting for manual review."""

    review_timeout: float = 900.0
    """Maximum wait time in seconds for a pending manual review decision."""

    review_mode: str = "block"
    """How to handle pending manual reviews. ``"block"`` (default): poll until
    a decision arrives or timeout expires. ``"detach"``: return a
    :class:`~ledgix_python.PendingApproval` immediately so the caller can
    resume later via :meth:`~ledgix_python.PendingApproval.wait_async`."""

    max_retries: int = 3
    """Number of retry attempts for transient failures (connection errors, 5xx responses)."""

    retry_base_delay: float = 0.5
    """Base delay in seconds for exponential backoff between retries (full jitter applied)."""

    decision_cache_enabled: bool = False
    """Enable the in-process decision cache.  Off by default — opt-in for safety.
    When enabled, approved decisions are memoized; subsequent identical tool
    calls skip the LLM judge and call /mint-token for a fresh A-JWT instead.
    """

    decision_cache_ttl_seconds: float = 60.0
    """TTL (seconds) for cached decision envelopes."""

    decision_cache_max_entries: int = 1000
    """Maximum number of decision envelopes to keep in memory."""

    principal_id: str | None = None
    """Advisory OIDC ``sub`` of the human on whose behalf the agent acts.
    Sent as ``human_principal`` in every clearance request.  Can be overridden
    per-call via ``on_behalf_of`` argument.  Env: ``LEDGIX_PRINCIPAL_ID``."""

    jwks_ttl_seconds: int = 300
    """How long (seconds) the cached JWKS is considered fresh before a key-miss
    triggers a refetch. Default 5 minutes matches the Vault's rotation cadence.
    Env: ``LEDGIX_JWKS_TTL_SECONDS``."""

    replay_cache_size: int = 10_000
    """Maximum number of consumed A-JWT jtis held in the in-process replay
    cache. When the limit is reached the oldest entries are evicted (LRU-TTL).
    Env: ``LEDGIX_REPLAY_CACHE_SIZE``."""

    max_token_lifetime_seconds: float = 330.0
    """TTL for entries in the replay cache (seconds). Should be at least
    ``VAULT_JWT_TTL + 30`` to cover clock skew. Default 330 = 5 min TTL + 30s.
    Env: ``LEDGIX_MAX_TOKEN_LIFETIME_SECONDS``."""
