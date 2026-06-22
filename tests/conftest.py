import pytest
import respx
import httpx
from unittest.mock import AsyncMock

from wazuh_mcp.config import WazuhSettings
from wazuh_mcp.auth import JWTManager
from wazuh_mcp.client import WazuhClient

MOCK_TOKEN = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.test.signature"


@pytest.fixture(scope="session")
def mock_settings() -> WazuhSettings:
    return WazuhSettings(
        wazuh_host="test-wazuh",
        wazuh_port=55000,
        wazuh_user="test_user",
        wazuh_password="test_password",
        wazuh_verify_ssl=True,
        jwt_refresh_margin=60,
        request_timeout=10,
        max_retries=3,
    )


@pytest.fixture
def mock_token() -> str:
    return MOCK_TOKEN


@pytest.fixture
def mock_auth(mock_settings: WazuhSettings, mock_token: str) -> JWTManager:
    auth = JWTManager(mock_settings)
    auth.get_token = AsyncMock(return_value=mock_token)
    return auth


@pytest.fixture
def mock_client(mock_settings: WazuhSettings, mock_auth: JWTManager) -> WazuhClient:
    return WazuhClient(mock_settings, mock_auth)


@pytest.fixture
def wazuh_api(mock_settings: WazuhSettings):
    with respx.mock(base_url=mock_settings.base_url, assert_all_called=False) as rx:
        rx.post("/security/user/authenticate").mock(
            return_value=httpx.Response(200, json={
                "data": {"token": "test-jwt-token"},
                "error": 0,
            })
        )
        yield rx
