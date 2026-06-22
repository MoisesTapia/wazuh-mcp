"""Security configuration tests (Fix A — HTTP auth, Fix B — SSL)."""
from __future__ import annotations

import warnings

import httpx
import pytest

from wazuh_mcp.config import WazuhSettings
from wazuh_mcp.server import _BearerAuthMiddleware, _check_http_security


# ── Helpers ───────────────────────────────────────────────────────────────────


def _settings(**overrides) -> WazuhSettings:
    """Build a WazuhSettings instance for security tests."""
    base = dict(
        wazuh_user="u",
        wazuh_password="p",
        wazuh_host="localhost",
        wazuh_port=55000,
        wazuh_verify_ssl=True,
    )
    base.update(overrides)
    return WazuhSettings(**base)


# ── Fix A: HTTP binding & authentication ──────────────────────────────────────


def test_http_mode_without_api_key_raises_value_error():
    """Starting in HTTP mode without MCP_API_KEY must fail with a clear ValueError."""
    with pytest.raises(ValueError, match="MCP_API_KEY"):
        _check_http_security("http", api_key=None)


def test_stdio_mode_without_api_key_does_not_raise():
    """stdio transport requires no API key — must not raise."""
    _check_http_security("stdio", api_key=None)   # should be silent


async def test_http_request_without_authorization_header_returns_401():
    """HTTP requests without an Authorization header must receive 401 Unauthorized."""

    async def _ok_app(scope, receive, send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

    app = _BearerAuthMiddleware(_ok_app, api_key="super-secret-key")

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        resp = await client.get("/mcp")

    assert resp.status_code == 401
    assert resp.headers["content-type"] == "application/json"
    assert "www-authenticate" in resp.headers


async def test_http_request_with_valid_bearer_token_passes_through():
    """HTTP requests with a valid Bearer token must reach the underlying app."""

    async def _ok_app(scope, receive, send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

    api_key = "correct-horse-battery-staple"
    app = _BearerAuthMiddleware(_ok_app, api_key=api_key)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        resp = await client.get("/mcp", headers={"Authorization": f"Bearer {api_key}"})

    assert resp.status_code == 200


# ── Fix B: SSL verification ───────────────────────────────────────────────────


def test_ssl_disabled_with_remote_host_emits_user_warning():
    """WAZUH_VERIFY_SSL=false with a non-localhost host must emit a UserWarning."""
    with pytest.warns(UserWarning, match="MITM"):
        _settings(wazuh_host="wazuh.prod.example.com", wazuh_verify_ssl=False)


def test_ssl_disabled_with_localhost_emits_no_warning():
    """WAZUH_VERIFY_SSL=false with localhost must NOT emit any warning."""
    with warnings.catch_warnings():
        warnings.simplefilter("error")   # any warning → test failure
        _settings(wazuh_host="localhost", wazuh_verify_ssl=False)


def test_ssl_disabled_with_loopback_ip_emits_no_warning():
    """WAZUH_VERIFY_SSL=false with 127.0.0.1 must NOT emit any warning."""
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _settings(wazuh_host="127.0.0.1", wazuh_verify_ssl=False)


def test_ssl_disabled_with_ca_bundle_emits_no_warning():
    """When wazuh_ca_bundle is set, verify_ssl=False must not warn (CA re-enables SSL)."""
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _settings(
            wazuh_host="wazuh.prod.example.com",
            wazuh_verify_ssl=False,
            wazuh_ca_bundle="/var/ossec/etc/sslmanager.cert",
        )


def test_ssl_verify_property_returns_ca_bundle_path_when_set():
    """ssl_verify must return the CA bundle path so httpx uses it for verification."""
    s = _settings(
        wazuh_host="wazuh.prod.example.com",
        wazuh_ca_bundle="/path/to/ca.pem",
    )
    assert s.ssl_verify == "/path/to/ca.pem"


def test_ssl_verify_property_returns_bool_when_no_ca_bundle():
    """ssl_verify must return the verify_ssl bool when no CA bundle is configured."""
    assert _settings(wazuh_verify_ssl=True).ssl_verify is True
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        s = _settings(wazuh_host="remote", wazuh_verify_ssl=False)
    assert s.ssl_verify is False
