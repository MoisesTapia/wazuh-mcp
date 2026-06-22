import pytest
import httpx
from fastmcp import FastMCP

from wazuh_mcp.tools import experimental

SUCCESS = {
    "data": {"affected_items": [{"agent_id": "001"}], "total_affected_items": 1},
    "error": 0,
}
EMPTY = {"data": {"affected_items": []}, "error": 0}


@pytest.fixture
async def fns(mock_client):
    mcp = FastMCP("test")
    experimental.register(mcp, mock_client)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


async def test_get_all_agents_hardware(fns, wazuh_api):
    wazuh_api.get("/experimental/syscollector/hardware").mock(
        return_value=httpx.Response(200, json=SUCCESS)
    )
    result = await fns["get_all_agents_hardware"]()
    assert result["error"] == 0


async def test_get_all_agents_hardware_with_filter(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.get("/experimental/syscollector/hardware").mock(side_effect=capture)
    await fns["get_all_agents_hardware"](agents_list="001,002", limit=5)
    assert captured["params"]["agents_list"] == "001,002"
    assert captured["params"]["limit"] == "5"


async def test_get_all_agents_os(fns, wazuh_api):
    wazuh_api.get("/experimental/syscollector/os").mock(
        return_value=httpx.Response(200, json=SUCCESS)
    )
    result = await fns["get_all_agents_os"]()
    assert result["error"] == 0


async def test_get_all_agents_packages_name_filter(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.get("/experimental/syscollector/packages").mock(side_effect=capture)
    await fns["get_all_agents_packages"](package_name="openssl")
    assert captured["params"]["name"] == "openssl"


async def test_clear_all_agents_rootcheck(fns, wazuh_api):
    wazuh_api.delete("/experimental/rootcheck").mock(
        return_value=httpx.Response(200, json=EMPTY)
    )
    result = await fns["clear_all_agents_rootcheck"]()
    assert result["error"] == 0


async def test_clear_all_agents_syscheck(fns, wazuh_api):
    wazuh_api.delete("/experimental/syscheck").mock(
        return_value=httpx.Response(200, json=EMPTY)
    )
    result = await fns["clear_all_agents_syscheck"](agents_list="001")
    assert result["error"] == 0


async def test_get_all_agents_hotfixes(fns, wazuh_api):
    wazuh_api.get("/experimental/syscollector/hotfixes").mock(
        return_value=httpx.Response(200, json=SUCCESS)
    )
    result = await fns["get_all_agents_hotfixes"](hotfix="KB4562830")
    assert result["error"] == 0
