import pytest
import httpx
from fastmcp import FastMCP

from wazuh_mcp.client import WazuhAPIError
from wazuh_mcp.tools import groups

GROUP_ITEM = {"name": "default", "count": 5, "configSum": "abc", "mergedSum": "def"}
SUCCESS = {
    "data": {"affected_items": [GROUP_ITEM], "total_affected_items": 1, "failed_items": []},
    "error": 0,
}


@pytest.fixture
async def fns(mock_client):
    mcp = FastMCP("test")
    groups.register(mcp, mock_client)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


# ── list_groups ───────────────────────────────────────────────────────────────

async def test_list_groups_happy_path(fns, wazuh_api):
    wazuh_api.get("/groups").mock(return_value=httpx.Response(200, json=SUCCESS))
    result = await fns["list_groups"]()
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["name"] == "default"


async def test_list_groups_403(fns, wazuh_api):
    wazuh_api.get("/groups").mock(
        return_value=httpx.Response(403, json={"detail": "Permiso denegado"})
    )
    with pytest.raises(WazuhAPIError) as exc:
        await fns["list_groups"]()
    assert "Permission denied" in str(exc.value)


async def test_list_groups_no_optional_params(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.get("/groups").mock(side_effect=capture)
    await fns["list_groups"]()
    assert "group_id" not in captured["params"]
    assert "limit" not in captured["params"]


# ── create_group ──────────────────────────────────────────────────────────────

async def test_create_group_happy_path(fns, wazuh_api):
    payload = {
        "data": {"affected_items": [{"name": "linux-servers"}],
                 "total_affected_items": 1, "failed_items": []},
        "error": 0,
    }
    wazuh_api.post("/groups").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["create_group"](group_id="linux-servers")
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["name"] == "linux-servers"


async def test_create_group_403(fns, wazuh_api):
    wazuh_api.post("/groups").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["create_group"](group_id="linux-servers")


# ── get_agents_in_group ───────────────────────────────────────────────────────

async def test_get_agents_in_group_happy_path(fns, wazuh_api):
    agent_payload = {
        "data": {
            "affected_items": [{"id": "001", "name": "agent-test", "status": "active"}],
            "total_affected_items": 1, "failed_items": [],
        },
        "error": 0,
    }
    wazuh_api.get("/groups/default/agents").mock(return_value=httpx.Response(200, json=agent_payload))
    result = await fns["get_agents_in_group"](group_id="default")
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["id"] == "001"


async def test_get_agents_in_group_403(fns, wazuh_api):
    wazuh_api.get("/groups/default/agents").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["get_agents_in_group"](group_id="default")


# ── delete_groups ─────────────────────────────────────────────────────────────

async def test_delete_groups_happy_path(fns, wazuh_api):
    wazuh_api.delete("/groups").mock(return_value=httpx.Response(200, json=SUCCESS))
    result = await fns["delete_groups"](groups_list="old-group")
    assert result["error"] == 0


async def test_delete_groups_403(fns, wazuh_api):
    wazuh_api.delete("/groups").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["delete_groups"](groups_list="old-group")


async def test_delete_groups_sends_groups_list_param(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"data": {"affected_items": []}, "error": 0})

    wazuh_api.delete("/groups").mock(side_effect=capture)
    await fns["delete_groups"](groups_list="old-group")
    assert captured["params"]["groups_list"] == "old-group"
