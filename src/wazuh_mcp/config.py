from __future__ import annotations

import warnings
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class WazuhSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # ── Wazuh API ─────────────────────────────────────────────────────────────
    wazuh_host: str = "localhost"
    wazuh_port: int = 55000
    wazuh_user: str
    wazuh_password: str
    wazuh_verify_ssl: bool = True
    # Path to a CA bundle PEM file for production TLS verification.
    # When set, takes precedence over wazuh_verify_ssl and SSL IS verified.
    wazuh_ca_bundle: str | None = None
    jwt_refresh_margin: int = 60
    request_timeout: int = 30
    max_retries: int = 3

    # ── Audit / logging ───────────────────────────────────────────────────────
    log_level: str = "INFO"
    log_file: str | None = None   # if set, logs rotate here in addition to stderr
    audit_enabled: bool = True

    # ── MCP server (HTTP transport) ───────────────────────────────────────────
    mcp_transport: Literal["stdio", "http"] = "stdio"
    mcp_host: str = "127.0.0.1"   # loopback-only by default; never 0.0.0.0
    mcp_port: int = 8000
    # Required when mcp_transport="http". Generate with: openssl rand -hex 32
    mcp_api_key: str | None = None

    # ── Wazuh Indexer (OpenSearch) ────────────────────────────────────────────────
    # Wazuh 4.8.0+ almacena alertas y CVEs en el Indexer (puerto 9200).
    # La Manager REST API ya no expone estos datos.
    wazuh_indexer_host: str | None = None
    wazuh_indexer_port: int = 9200
    wazuh_indexer_user: str = "admin"
    wazuh_indexer_password: str = "admin"
    wazuh_indexer_verify_ssl: bool = False

    # ── Computed helpers ──────────────────────────────────────────────────────

    @property
    def base_url(self) -> str:
        return f"https://{self.wazuh_host}:{self.wazuh_port}"

    @property
    def ssl_verify(self) -> bool | str:
        """httpx-compatible SSL verify value.

        Returns the CA bundle path when set (SSL verified against custom CA),
        otherwise falls back to wazuh_verify_ssl (True = system CAs, False = skip).
        """
        return self.wazuh_ca_bundle if self.wazuh_ca_bundle else self.wazuh_verify_ssl

    @property
    def indexer_url(self) -> str | None:
        if not self.wazuh_indexer_host:
            return None
        return f"https://{self.wazuh_indexer_host}:{self.wazuh_indexer_port}"

    @property
    def indexer_configured(self) -> bool:
        return self.wazuh_indexer_host is not None

    # ── Validators ────────────────────────────────────────────────────────────

    @model_validator(mode="after")
    def _warn_ssl_disabled_on_remote_host(self) -> WazuhSettings:
        """Emit a UserWarning when TLS verification is off and the host is remote.

        The warning is suppressed when wazuh_ca_bundle is set because the CA
        bundle re-enables verification against a trusted certificate.
        """
        if (
            not self.wazuh_verify_ssl
            and self.wazuh_ca_bundle is None
            and self.wazuh_host not in ("localhost", "127.0.0.1")
        ):
            warnings.warn(
                f"WAZUH_VERIFY_SSL=false with remote host '{self.wazuh_host}' "
                "exposes credentials and tokens to MITM attacks. "
                "In production use WAZUH_VERIFY_SSL=true "
                "or WAZUH_CA_BUNDLE=/path/to/ca.pem.",
                UserWarning,
                stacklevel=2,
            )
        return self
