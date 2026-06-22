import pytest
import httpx
from fastmcp import FastMCP

from wazuh_mcp.tools import ciscat

SUCCESS = {
    "data": {
        "affected_items": [
            {"benchmark": "CIS Ubuntu Linux 20.04 LTS", "score": 75, "pass": 100, "fail": 25}
        ]
    },
    "error": 0,
}


@pytest.fixture
async def fns(mock_client):
    mcp = FastMCP("test")
    ciscat.register(mcp, mock_client)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


async def test_get_ciscat_results_happy_path(fns, wazuh_api):
    wazuh_api.get("/ciscat/001/results").mock(return_value=httpx.Response(200, json=SUCCESS))
    result = await fns["get_ciscat_results"](agent_id="001")
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["score"] == 75


async def test_get_ciscat_results_with_benchmark(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.get("/ciscat/001/results").mock(side_effect=capture)
    await fns["get_ciscat_results"](agent_id="001", benchmark="CIS Ubuntu Linux 20.04 LTS")
    assert "CIS Ubuntu" in captured["params"]["benchmark"]


async def test_get_ciscat_results_no_none_params(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.get("/ciscat/001/results").mock(side_effect=capture)
    await fns["get_ciscat_results"](agent_id="001")
    assert "benchmark" not in captured["params"]
    assert "score" not in captured["params"]
