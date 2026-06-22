import pytest
import httpx
from fastmcp import FastMCP

from wazuh_mcp.tools import overview

OVERVIEW_RESULT = {
    "data": {
        "agent": {
            "status": {"active": 10, "disconnected": 2, "pending": 1, "never_connected": 0},
            "os": {"ubuntu": 8, "windows": 4},
            "version": {"v4.7.0": 12},
        }
    },
    "error": 0,
}


@pytest.fixture
async def fns(mock_client):
    mcp = FastMCP("test")
    overview.register(mcp, mock_client)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


async def test_get_agents_overview_happy_path(fns, wazuh_api):
    wazuh_api.get("/overview/agents").mock(
        return_value=httpx.Response(200, json=OVERVIEW_RESULT)
    )
    result = await fns["get_agents_overview"]()
    assert result["error"] == 0
    assert result["data"]["agent"]["status"]["active"] == 10


async def test_get_agents_overview_status_counts(fns, wazuh_api):
    wazuh_api.get("/overview/agents").mock(
        return_value=httpx.Response(200, json=OVERVIEW_RESULT)
    )
    result = await fns["get_agents_overview"]()
    status = result["data"]["agent"]["status"]
    assert "active" in status
    assert "disconnected" in status


async def test_get_agents_overview_no_params(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=OVERVIEW_RESULT)

    wazuh_api.get("/overview/agents").mock(side_effect=capture)
    await fns["get_agents_overview"]()
    assert captured["params"] == {}
