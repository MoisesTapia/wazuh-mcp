import pytest
import httpx
import respx
from unittest.mock import AsyncMock, patch

from wazuh_mcp.client import WazuhClient, WazuhAPIError
from wazuh_mcp.config import WazuhSettings
from wazuh_mcp.auth import JWTManager

BASE = "https://test-wazuh:55000"


@pytest.fixture
def settings() -> WazuhSettings:
    return WazuhSettings(
        wazuh_host="test-wazuh",
        wazuh_port=55000,
        wazuh_user="u",
        wazuh_password="p",
        wazuh_verify_ssl=True,
        max_retries=3,
        request_timeout=5,
    )


@pytest.fixture
def auth(settings) -> JWTManager:
    a = JWTManager(settings)
    a.get_token = AsyncMock(return_value="test-token")
    return a


@pytest.fixture
def client(settings, auth) -> WazuhClient:
    return WazuhClient(settings, auth)


# ── retry on 429 ──────────────────────────────────────────────────────────────

async def test_retry_on_429(client):
    call_count = 0

    with respx.mock(base_url=BASE, assert_all_called=False) as rx:
        def respond_429(request, route):
            nonlocal call_count
            call_count += 1
            return httpx.Response(429, json={"detail": "Too Many Requests"})

        rx.get("/agents").mock(side_effect=respond_429)

        with patch("asyncio.sleep"):
            with pytest.raises(WazuhAPIError):
                await client.get("/agents")

    assert call_count == 3  # max_retries attempts


# ── retry on connect error ─────────────────────────────────────────────────────

async def test_retry_on_connect_error(client):
    call_count = 0

    with respx.mock(base_url=BASE, assert_all_called=False) as rx:
        def raise_connect(request, route):
            nonlocal call_count
            call_count += 1
            raise httpx.ConnectError("Connection refused")

        rx.get("/agents").mock(side_effect=raise_connect)

        with patch("asyncio.sleep"):
            with pytest.raises(WazuhAPIError) as exc:
                await client.get("/agents")

    assert "attempts" in str(exc.value)
    assert call_count == 3


# ── 401 invalidates token and retries ─────────────────────────────────────────

async def test_401_refreshes_token(client, auth):
    call_count = 0

    with respx.mock(base_url=BASE, assert_all_called=False) as rx:
        def respond(request, route):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return httpx.Response(401, json={"detail": "Unauthorized"})
            return httpx.Response(200, json={"data": {}, "error": 0})

        rx.get("/agents").mock(side_effect=respond)

        result = await client.get("/agents")

    assert result["error"] == 0
    assert auth.get_token.call_count >= 2


# ── _clean_params removes None ─────────────────────────────────────────────────

def test_clean_params_removes_none():
    result = WazuhClient._clean_params({"a": 1, "b": None, "c": "val", "d": None})
    assert result == {"a": 1, "c": "val"}


def test_clean_params_all_none_returns_none():
    result = WazuhClient._clean_params({"a": None, "b": None})
    assert result is None


def test_clean_params_none_input_returns_none():
    result = WazuhClient._clean_params(None)
    assert result is None


def test_clean_params_keeps_falsy_non_none():
    result = WazuhClient._clean_params({"a": 0, "b": False, "c": "", "d": None})
    assert result == {"a": 0, "b": False, "c": ""}


# ── WazuhAPIError has status_code and response_body ───────────────────────────

async def test_api_error_has_status_code(client):
    with respx.mock(base_url=BASE, assert_all_called=False) as rx:
        rx.get("/agents").mock(
            return_value=httpx.Response(403, json={"detail": "Forbidden"})
        )
        with pytest.raises(WazuhAPIError) as exc:
            await client.get("/agents")

    assert exc.value.status_code == 403


async def test_api_error_has_response_body(client):
    with respx.mock(base_url=BASE, assert_all_called=False) as rx:
        rx.get("/agents").mock(
            return_value=httpx.Response(400, json={"detail": "Bad request param"})
        )
        with pytest.raises(WazuhAPIError) as exc:
            await client.get("/agents")

    assert exc.value.response_body is not None
    assert "detail" in exc.value.response_body


# ── none params don't reach API ────────────────────────────────────────────────

async def test_none_params_not_sent(client):
    with respx.mock(base_url=BASE, assert_all_called=False) as rx:
        captured: dict = {}

        def capture(request, route):
            captured["params"] = dict(request.url.params)
            return httpx.Response(200, json={"data": {}, "error": 0})

        rx.get("/agents").mock(side_effect=capture)
        await client.get("/agents", params={"status": None, "limit": 10})

    assert "status" not in captured["params"]
    assert captured["params"]["limit"] == "10"
