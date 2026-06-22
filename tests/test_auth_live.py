"""Integration tests — require a live Wazuh instance via Docker Compose.

Run with:
    make docker-up
    make test-integration
"""

import asyncio
import time
import pytest
import httpx

from wazuh_mcp.config import WazuhSettings
from wazuh_mcp.auth import JWTManager
from wazuh_mcp.client import WazuhClient

# Wazuh API credentials — must match docker-compose.yml API_USERNAME / API_PASSWORD
WAZUH_API_HOST = "localhost"
WAZUH_API_PORT = 55000
WAZUH_API_USER = "wazuh-wui"
WAZUH_API_PASS = "MyS3cr37P450r.*-"

HEALTHCHECK_URL = f"https://{WAZUH_API_HOST}:{WAZUH_API_PORT}/"
HEALTHCHECK_TIMEOUT = 180


@pytest.fixture(scope="module")
def live_settings() -> WazuhSettings:
    return WazuhSettings(
        wazuh_host=WAZUH_API_HOST,
        wazuh_port=WAZUH_API_PORT,
        wazuh_user=WAZUH_API_USER,
        wazuh_password=WAZUH_API_PASS,
        wazuh_verify_ssl=False,
    )


@pytest.fixture(scope="module", autouse=True)
def wait_for_wazuh_api():
    """Wait for the Wazuh REST API to be ready (assumes docker compose is already up)."""
    deadline = time.time() + HEALTHCHECK_TIMEOUT
    last_err: Exception | None = None

    while time.time() < deadline:
        try:
            with httpx.Client(verify=False, timeout=5) as c:
                resp = c.get(
                    HEALTHCHECK_URL,
                    auth=(WAZUH_API_USER, WAZUH_API_PASS),
                )
                if resp.status_code == 200 and resp.json().get("error") == 0:
                    return
        except Exception as exc:
            last_err = exc
        time.sleep(5)

    pytest.fail(
        f"Wazuh API no respondió en {HEALTHCHECK_TIMEOUT}s. "
        f"Asegúrate de haber ejecutado: make docker-up\n"
        f"Último error: {last_err}"
    )


@pytest.mark.integration
async def test_jwt_obtained(live_settings: WazuhSettings):
    """Authentication returns a non-empty JWT."""
    auth = JWTManager(live_settings)
    token = await auth.get_token()
    assert token and len(token) > 20


@pytest.mark.integration
async def test_ping_wazuh_returns_no_error(live_settings: WazuhSettings):
    """GET / returns error:0 from Wazuh API."""
    auth = JWTManager(live_settings)
    wazuh_client = WazuhClient(live_settings, auth)
    result = await wazuh_client.get("/")
    assert result.get("error") == 0


@pytest.mark.integration
async def test_token_cached(live_settings: WazuhSettings):
    """Consecutive get_token() calls return the same token (cached)."""
    auth = JWTManager(live_settings)
    token1 = await auth.get_token()
    token2 = await auth.get_token()
    assert token1 == token2


@pytest.mark.integration
async def test_token_renewed_after_invalidate(live_settings: WazuhSettings):
    """Invalidating the token causes re-authentication and issues a new token."""
    auth = JWTManager(live_settings)
    token1 = await auth.get_token()
    auth.invalidate()
    await asyncio.sleep(1)
    token2 = await auth.get_token()
    assert token2 and token2 != token1


@pytest.mark.integration
async def test_list_agents(live_settings: WazuhSettings):
    """GET /agents returns a valid response."""
    auth = JWTManager(live_settings)
    client = WazuhClient(live_settings, auth)
    result = await client.get("/agents")
    assert result.get("error") == 0
    assert "data" in result


@pytest.mark.integration
async def test_manager_info(live_settings: WazuhSettings):
    """GET /manager/info returns version info."""
    auth = JWTManager(live_settings)
    client = WazuhClient(live_settings, auth)
    result = await client.get("/manager/info")
    assert result.get("error") == 0
    items = result["data"]["affected_items"]
    assert len(items) > 0
    assert "version" in items[0]
