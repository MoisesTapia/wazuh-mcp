import json
import pytest
import httpx
from fastmcp import FastMCP

from wazuh_mcp.client import WazuhAPIError
from wazuh_mcp.tools import agents

AGENT_ITEM = {
    "id": "001", "name": "agent-test", "ip": "192.168.1.1",
    "status": "active", "os": {"platform": "ubuntu"}, "version": "4.7.0",
}
SUCCESS = {
    "data": {"affected_items": [AGENT_ITEM], "total_affected_items": 1, "failed_items": []},
    "error": 0,
}


@pytest.fixture
async def fns(mock_client):
    mcp = FastMCP("test")
    agents.register(mcp, mock_client)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


# ── list_agents ───────────────────────────────────────────────────────────────

async def test_list_agents_happy_path(fns, wazuh_api):
    wazuh_api.get("/agents").mock(return_value=httpx.Response(200, json=SUCCESS))
    result = await fns["list_agents"]()
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["id"] == "001"


async def test_list_agents_403(fns, wazuh_api):
    wazuh_api.get("/agents").mock(
        return_value=httpx.Response(403, json={"detail": "Permiso denegado"})
    )
    with pytest.raises(WazuhAPIError) as exc:
        await fns["list_agents"]()
    assert "Permission denied" in str(exc.value)


async def test_list_agents_no_extra_params(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.get("/agents").mock(side_effect=capture)
    await fns["list_agents"]()
    assert "status" not in captured["params"]
    assert "group" not in captured["params"]


async def test_list_agents_status_param_sent(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.get("/agents").mock(side_effect=capture)
    await fns["list_agents"](status="active")
    assert captured["params"]["status"] == "active"


# ── get_agent ─────────────────────────────────────────────────────────────────

async def test_get_agent_happy_path(fns, wazuh_api):
    wazuh_api.get("/agents").mock(return_value=httpx.Response(200, json=SUCCESS))
    result = await fns["get_agent"](agent_id="001")
    assert result["error"] == 0


async def test_get_agent_403(fns, wazuh_api):
    wazuh_api.get("/agents").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["get_agent"](agent_id="001")


async def test_get_agent_sends_agents_list_param(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.get("/agents").mock(side_effect=capture)
    await fns["get_agent"](agent_id="042")
    assert captured["params"]["agents_list"] == "042"


# ── add_agent ─────────────────────────────────────────────────────────────────

async def test_add_agent_happy_path(fns, wazuh_api):
    payload = {
        "data": {"affected_items": [{"id": "002", "key": "abc123"}],
                 "total_affected_items": 1, "failed_items": []},
        "error": 0,
    }
    wazuh_api.post("/agents").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["add_agent"](name="new-agent")
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["id"] == "002"


async def test_add_agent_403(fns, wazuh_api):
    wazuh_api.post("/agents").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["add_agent"](name="new-agent")


async def test_add_agent_optional_ip_omitted(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"data": {"affected_items": []}, "error": 0})

    wazuh_api.post("/agents").mock(side_effect=capture)
    await fns["add_agent"](name="agent-no-ip")
    assert "ip" not in captured["body"]


# ── delete_agents ─────────────────────────────────────────────────────────────

async def test_delete_agents_happy_path(fns, wazuh_api):
    wazuh_api.delete("/agents").mock(return_value=httpx.Response(200, json=SUCCESS))
    result = await fns["delete_agents"](agents_list="001", status="disconnected")
    assert result["error"] == 0


async def test_delete_agents_403(fns, wazuh_api):
    wazuh_api.delete("/agents").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["delete_agents"](agents_list="001", status="disconnected")


async def test_delete_agents_purge_param_sent(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"data": {"affected_items": []}, "error": 0})

    wazuh_api.delete("/agents").mock(side_effect=capture)
    await fns["delete_agents"](agents_list="001", status="disconnected", purge=True)
    assert captured["params"]["purge"].lower() == "true"


# ── restart_agent ─────────────────────────────────────────────────────────────

async def test_restart_agent_happy_path(fns, wazuh_api):
    payload = {"data": {"affected_items": [{"id": "001"}], "total_affected_items": 1, "failed_items": []}, "error": 0}
    wazuh_api.put("/agents/001/restart").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["restart_agent"](agent_id="001")
    assert result["error"] == 0


async def test_restart_agent_403(fns, wazuh_api):
    wazuh_api.put("/agents/001/restart").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["restart_agent"](agent_id="001")
