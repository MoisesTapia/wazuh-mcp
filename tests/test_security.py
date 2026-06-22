import pytest
import httpx
from fastmcp import FastMCP

from wazuh_mcp.client import WazuhAPIError
from wazuh_mcp.tools import security

USER_ITEM = {"id": 1, "username": "admin", "allow_run_as": False, "roles": [1]}
SUCCESS = {
    "data": {"affected_items": [USER_ITEM], "total_affected_items": 1, "failed_items": []},
    "error": 0,
}


@pytest.fixture
async def fns(mock_client):
    mcp = FastMCP("test")
    security.register(mcp, mock_client)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


# ── list_users ────────────────────────────────────────────────────────────────

async def test_list_users_happy_path(fns, wazuh_api):
    wazuh_api.get("/security/users").mock(return_value=httpx.Response(200, json=SUCCESS))
    result = await fns["list_users"]()
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["username"] == "admin"


async def test_list_users_403(fns, wazuh_api):
    wazuh_api.get("/security/users").mock(
        return_value=httpx.Response(403, json={"detail": "Permiso denegado"})
    )
    with pytest.raises(WazuhAPIError) as exc:
        await fns["list_users"]()
    assert "Permission denied" in str(exc.value)


async def test_list_users_no_extra_params(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.get("/security/users").mock(side_effect=capture)
    await fns["list_users"]()
    assert "user_ids" not in captured["params"]
    assert "limit" not in captured["params"]


# ── create_user ───────────────────────────────────────────────────────────────

async def test_create_user_happy_path(fns, wazuh_api):
    payload = {
        "data": {"affected_items": [{"id": 5, "username": "newuser"}],
                 "total_affected_items": 1, "failed_items": []},
        "error": 0,
    }
    wazuh_api.post("/security/users").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["create_user"](username="newuser", password="Test@1234")
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["username"] == "newuser"


async def test_create_user_403(fns, wazuh_api):
    wazuh_api.post("/security/users").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["create_user"](username="newuser", password="Test@1234")


# ── delete_users ──────────────────────────────────────────────────────────────

async def test_delete_users_happy_path(fns, wazuh_api):
    wazuh_api.delete("/security/users").mock(return_value=httpx.Response(200, json=SUCCESS))
    result = await fns["delete_users"](user_ids="5")
    assert result["error"] == 0


async def test_delete_users_403(fns, wazuh_api):
    wazuh_api.delete("/security/users").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["delete_users"](user_ids="5")


# ── get_security_config ───────────────────────────────────────────────────────

async def test_get_security_config_happy_path(fns, wazuh_api):
    payload = {
        "data": {
            "affected_items": [{"auth_token_exp_timeout": 900, "rbac_mode": "white"}],
            "total_affected_items": 1, "failed_items": [],
        },
        "error": 0,
    }
    wazuh_api.get("/security/config").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["get_security_config"]()
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["rbac_mode"] == "white"


async def test_get_security_config_403(fns, wazuh_api):
    wazuh_api.get("/security/config").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["get_security_config"]()


# ── revoke_all_tokens ─────────────────────────────────────────────────────────

async def test_revoke_all_tokens_happy_path(fns, wazuh_api):
    payload = {"data": {"affected_items": [], "total_affected_items": 0, "failed_items": []}, "error": 0}
    wazuh_api.put("/security/user/revoke").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["revoke_all_tokens"]()
    assert result["error"] == 0


async def test_revoke_all_tokens_403(fns, wazuh_api):
    wazuh_api.put("/security/user/revoke").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["revoke_all_tokens"]()
