import pytest
import httpx
from fastmcp import FastMCP

from wazuh_mcp.tools import rootcheck

SUCCESS = {
    "data": {"affected_items": [{"log": "Rootkit detected", "status": "outstanding"}]},
    "error": 0,
}
EMPTY = {"data": {"affected_items": []}, "error": 0}


@pytest.fixture
async def fns(mock_client):
    mcp = FastMCP("test")
    rootcheck.register(mcp, mock_client)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


async def test_get_rootcheck_results_happy_path(fns, wazuh_api):
    wazuh_api.get("/rootcheck/001").mock(return_value=httpx.Response(200, json=SUCCESS))
    result = await fns["get_rootcheck_results"](agent_id="001")
    assert "_wazuh_external_data" in result
    content = result["_wazuh_external_data"]["content"]
    assert content["error"] == 0
    assert content["data"]["affected_items"][0]["status"] == "outstanding"


async def test_get_rootcheck_results_status_filter(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.get("/rootcheck/001").mock(side_effect=capture)
    await fns["get_rootcheck_results"](agent_id="001", status="outstanding")
    assert captured["params"]["status"] == "outstanding"


async def test_get_rootcheck_last_scan(fns, wazuh_api):
    scan_result = {
        "data": {"affected_items": [{"start": "2024-01-01 00:00:00", "end": "2024-01-01 00:05:00"}]},
        "error": 0,
    }
    wazuh_api.get("/rootcheck/001/last_scan").mock(
        return_value=httpx.Response(200, json=scan_result)
    )
    result = await fns["get_rootcheck_last_scan"](agent_id="001")
    assert result["error"] == 0


async def test_clear_rootcheck_results(fns, wazuh_api):
    wazuh_api.delete("/rootcheck/001").mock(return_value=httpx.Response(200, json=EMPTY))
    result = await fns["clear_rootcheck_results"](agent_id="001")
    assert result["error"] == 0


async def test_run_rootcheck_scan(fns, wazuh_api):
    wazuh_api.put("/rootcheck").mock(return_value=httpx.Response(200, json=EMPTY))
    result = await fns["run_rootcheck_scan"](agents_list="001,002")
    assert result["error"] == 0
