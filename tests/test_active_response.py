import pytest
import httpx
from fastmcp import FastMCP

from wazuh_mcp.tools import active_response

SUCCESS = {
    "data": {"affected_agents": ["001", "002"], "failed_agents": []},
    "error": 0,
}


@pytest.fixture
async def fns(mock_client):
    mcp = FastMCP("test")
    active_response.register(mcp, mock_client)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


async def test_run_active_response_happy_path(fns, wazuh_api):
    wazuh_api.put("/active-response").mock(return_value=httpx.Response(200, json=SUCCESS))
    result = await fns["run_active_response"](command="restart-wazuh")
    assert result["error"] == 0
    assert "001" in result["data"]["affected_agents"]


async def test_run_active_response_with_agents(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.put("/active-response").mock(side_effect=capture)
    await fns["run_active_response"](command="firewall-drop", agents_list="001,002")
    assert captured["params"]["agents_list"] == "001,002"


async def test_run_active_response_with_body(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        import json
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.put("/active-response").mock(side_effect=capture)
    await fns["run_active_response"](
        command="firewall-drop",
        arguments=["-", "null", "0", "0"],
        alert={"rule": {"id": "100001"}},
    )
    assert captured["body"]["command"] == "firewall-drop"
    assert captured["body"]["arguments"] == ["-", "null", "0", "0"]
    assert captured["body"]["alert"]["rule"]["id"] == "100001"
