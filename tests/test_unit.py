"""Unit tests — no network, no Docker."""

import time
import pytest
import respx
import httpx
from unittest.mock import patch

from wazuh_mcp.config import WazuhSettings
from wazuh_mcp.auth import JWTManager
from wazuh_mcp.client import WazuhClient, WazuhAPIError

BASE = "https://test-wazuh:55000"
AUTH_URL = f"{BASE}/security/user/authenticate"
PING_URL = f"{BASE}/"


# ── Config ───────────────────────────────────────────────────────────────────

def test_config_base_url(mock_settings: WazuhSettings):
    assert mock_settings.base_url == "https://test-wazuh:55000"


def test_config_defaults():
    # Provide all values explicitly so the .env on disk doesn't interfere
    s = WazuhSettings(
        wazuh_user="u",
        wazuh_password="p",
        wazuh_host="localhost",
        wazuh_port=55000,
        wazuh_verify_ssl=True,
        jwt_refresh_margin=60,
    )
    assert s.wazuh_host == "localhost"
    assert s.wazuh_port == 55000
    assert s.wazuh_verify_ssl is True
    assert s.jwt_refresh_margin == 60


# ── JWTManager ───────────────────────────────────────────────────────────────

@respx.mock
async def test_jwt_manager_authenticates(mock_settings: WazuhSettings):
    respx.post(AUTH_URL).mock(
        return_value=httpx.Response(
            200, json={"data": {"token": "tok-abc123"}}
        )
    )
    auth = JWTManager(mock_settings)
    token = await auth.get_token()
    assert token == "tok-abc123"


@respx.mock
async def test_jwt_manager_caches_token(mock_settings: WazuhSettings):
    call_count = 0

    def handler(request):
        nonlocal call_count
        call_count += 1
        return httpx.Response(200, json={"data": {"token": "cached-tok"}})

    respx.post(AUTH_URL).mock(side_effect=handler)
    auth = JWTManager(mock_settings)
    t1 = await auth.get_token()
    t2 = await auth.get_token()
    assert t1 == t2 == "cached-tok"
    assert call_count == 1  # only one HTTP call


@respx.mock
async def test_jwt_manager_invalidate_forces_refresh(mock_settings: WazuhSettings):
    tokens = iter(["first-tok", "second-tok"])
    respx.post(AUTH_URL).mock(
        side_effect=lambda _: httpx.Response(
            200, json={"data": {"token": next(tokens)}}
        )
    )
    auth = JWTManager(mock_settings)
    t1 = await auth.get_token()
    auth.invalidate()
    t2 = await auth.get_token()
    assert t1 == "first-tok"
    assert t2 == "second-tok"


@respx.mock
async def test_jwt_manager_raises_on_auth_failure(mock_settings: WazuhSettings):
    respx.post(AUTH_URL).mock(return_value=httpx.Response(401))
    auth = JWTManager(mock_settings)
    with pytest.raises(httpx.HTTPStatusError):
        await auth.get_token()


# ── WazuhClient ──────────────────────────────────────────────────────────────

@respx.mock
async def test_client_get_success(mock_client: WazuhClient, mock_settings: WazuhSettings):
    payload = {"error": 0, "data": {"title": "Wazuh API"}}
    respx.get(PING_URL).mock(return_value=httpx.Response(200, json=payload))
    result = await mock_client.get("/")
    assert result["error"] == 0


@respx.mock
async def test_client_maps_401_to_actionable_message(
    mock_client: WazuhClient, mock_settings: WazuhSettings
):
    respx.get(PING_URL).mock(return_value=httpx.Response(401, json={"detail": "Unauthorized"}))
    with pytest.raises(WazuhAPIError) as exc_info:
        await mock_client.get("/")
    assert "expired token" in str(exc_info.value)
    assert exc_info.value.status_code == 401


@respx.mock
async def test_client_maps_403(mock_client: WazuhClient):
    respx.get(PING_URL).mock(
        return_value=httpx.Response(403, json={"detail": "insufficient permissions"})
    )
    with pytest.raises(WazuhAPIError) as exc_info:
        await mock_client.get("/")
    assert "Permission denied" in str(exc_info.value)
    assert exc_info.value.status_code == 403


@respx.mock
async def test_client_maps_400(mock_client: WazuhClient):
    respx.get(PING_URL).mock(
        return_value=httpx.Response(400, json={"detail": "bad param"})
    )
    with pytest.raises(WazuhAPIError) as exc_info:
        await mock_client.get("/")
    assert "Invalid request" in str(exc_info.value)
    assert exc_info.value.status_code == 400


@respx.mock
async def test_client_maps_429(mock_client: WazuhClient):
    # With retry, 429 is retried max_retries times and then raises a generic WazuhAPIError
    respx.get(PING_URL).mock(return_value=httpx.Response(429, json={}))
    with patch("asyncio.sleep"):
        with pytest.raises(WazuhAPIError) as exc_info:
            await mock_client.get("/")
    assert exc_info.value is not None


@respx.mock
async def test_client_post(mock_client: WazuhClient):
    respx.post(f"{BASE}/agents").mock(
        return_value=httpx.Response(200, json={"error": 0, "data": {"id": "099"}})
    )
    result = await mock_client.post("/agents", json={"name": "test-agent"})
    assert result["data"]["id"] == "099"


@respx.mock
async def test_client_connection_error_wraps_as_wazuh_error(mock_client: WazuhClient):
    # With retry, ConnectError is retried and then raises WazuhAPIError with "attempts"
    respx.get(PING_URL).mock(side_effect=httpx.ConnectError("refused"))
    with patch("asyncio.sleep"):
        with pytest.raises(WazuhAPIError) as exc_info:
            await mock_client.get("/")
    assert "attempts" in str(exc_info.value)
