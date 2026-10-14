"""Runtime settings, read from GXP_* environment variables."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GXP_", env_nested_delimiter="__")

    environment: str = "production"
    public_url: str = Field(description="Public HTTPS URL of this runtime (agent card, MCP host)")
    database_url: str = Field(description="SQLAlchemy async URL, e.g. postgresql+asyncpg://...")
    instance_id: str | None = Field(
        default=None, description="Audit chain prefix; defaults to the host name (pod name)"
    )

    signing_key_file: Path | None = Field(
        default=None, description="Ed25519 PEM for e-signature manifests and execution records"
    )
    audit_key_file: Path | None = Field(default=None, description="Ed25519 PEM for audit chains")
    trusted_public_keys_dir: Path | None = Field(
        default=None, description="Retired Ed25519 public keys (<kid>.pem) kept for verification"
    )
    dev_ephemeral_keys: bool = Field(
        default=False,
        description="Generate in-memory keys at start-up. Refused when environment=production.",
    )

    signer_issuer: str = Field(description="Enterprise OIDC issuer for human users and signers")
    signer_audience: str = Field(description="Audience (client id) of user and re-auth tokens")
    signer_jwks_url: str
    signer_roles_claim: str = "roles"
    signer_name_claim: str = "name"
    reauth_max_age_seconds: int = Field(default=300, ge=30, le=900)
    challenge_ttl_seconds: int = Field(default=300, ge=60, le=900)

    fabric_url: str | None = Field(
        default=None, description="agent-identity-fabric base URL; enables introspection/authorize"
    )
    agent_issuer: str | None = Field(
        default=None, description="Issuer of agent credentials (the fabric's issuer URL)"
    )
    agent_audience: str = "agent-platform"
    agent_jwks_url: str | None = None
    runtime_client_id: str | None = Field(
        default=None, description="This runtime's SPIFFE ID registered in the identity fabric"
    )
    workload_token_file: Path | None = Field(
        default=None, description="Projected service-account token used to obtain credentials"
    )

    policy_file: Path = Path("policies/gxp-runtime.yaml")
    approval_ttl_hours: int = Field(default=72, ge=1, le=720)
    max_clock_skew_seconds: int = Field(default=120, ge=5, le=600)
    max_activity_age_seconds: int = Field(default=900, ge=60, le=86400)
    connector_timeout_seconds: float = Field(default=30.0, gt=0, le=120)
    expiry_sweep_seconds: float = Field(default=60.0, gt=0)

    mcp_allowed_hosts: list[str] = Field(
        default_factory=list,
        description="Extra Host header values accepted by /mcp (e.g. in-cluster service names)",
    )

    log_level: str = "INFO"
    otlp_endpoint: str | None = None

    @model_validator(mode="after")
    def _consistency(self) -> Settings:
        parts = urlsplit(self.public_url)
        if parts.scheme not in {"https", "http"} or not parts.hostname:
            raise ValueError("public_url must be an absolute URL")
        if parts.scheme == "http" and self.environment == "production":
            raise ValueError("public_url must use https in production")
        if self.dev_ephemeral_keys:
            if self.environment == "production":
                raise ValueError("dev_ephemeral_keys cannot be used in production")
        else:
            missing = [
                name
                for name, value in (
                    ("GXP_SIGNING_KEY_FILE", self.signing_key_file),
                    ("GXP_AUDIT_KEY_FILE", self.audit_key_file),
                )
                if value is None
            ]
            if missing:
                raise ValueError(f"signing configuration incomplete: {missing}")
        if self.fabric_url is None and (self.agent_issuer is None or self.agent_jwks_url is None):
            raise ValueError(
                "configure GXP_FABRIC_URL, or GXP_AGENT_ISSUER and GXP_AGENT_JWKS_URL for "
                "offline verification of fabric-issued agent credentials"
            )
        if (self.runtime_client_id is None) != (self.workload_token_file is None):
            raise ValueError("GXP_RUNTIME_CLIENT_ID and GXP_WORKLOAD_TOKEN_FILE go together")
        if self.workload_token_file is not None and self.fabric_url is None:
            raise ValueError("runtime credentials require GXP_FABRIC_URL")
        return self

    @property
    def public_host(self) -> str:
        parts = urlsplit(self.public_url)
        return parts.netloc

    @property
    def mcp_hosts(self) -> list[str]:
        return [self.public_host, *self.mcp_allowed_hosts]

    @property
    def public_base(self) -> str:
        return self.public_url.rstrip("/")

    @property
    def approval_ttl(self) -> timedelta:
        return timedelta(hours=self.approval_ttl_hours)
