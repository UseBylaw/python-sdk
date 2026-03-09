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

    review_timeout: float = 300.0
    """Maximum wait time in seconds for a pending manual review decision."""
