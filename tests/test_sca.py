import pytest
import httpx
from fastmcp import FastMCP

from wazuh_mcp.tools import sca

SUCCESS = {
    "data": {"affected_items": [{"id": "cis_ubuntu20-04", "score": 85}], "total_affected_items": 1},
    "error": 0,
}


@pytest.fixture
async def fns(mock_client):
    mcp = FastMCP("test")
    sca.register(mcp, mock_client)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


async def test_get_sca_results_happy_path(fns, wazuh_api):
    wazuh_api.get("/sca/001").mock(return_value=httpx.Response(200, json=SUCCESS))
    result = await fns["get_sca_results"](agent_id="001")
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["score"] == 85


async def test_get_sca_results_with_filters(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.get("/sca/001").mock(side_effect=capture)
    await fns["get_sca_results"](agent_id="001", limit=10, offset=0)
    assert captured["params"]["limit"] == "10"
    assert captured["params"]["offset"] == "0"


async def test_get_sca_results_no_none_params(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.get("/sca/001").mock(side_effect=capture)
    await fns["get_sca_results"](agent_id="001")
    assert "name" not in captured["params"]
    assert "description" not in captured["params"]


async def test_get_sca_policy_checks_happy_path(fns, wazuh_api):
    checks_success = {
        "data": {"affected_items": [{"id": 1, "title": "Check SSH", "result": "passed"}]},
        "error": 0,
    }
    wazuh_api.get("/sca/001/checks/cis_ubuntu20-04").mock(
        return_value=httpx.Response(200, json=checks_success)
    )
    result = await fns["get_sca_policy_checks"](agent_id="001", policy_id="cis_ubuntu20-04")
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["result"] == "passed"


async def test_get_sca_policy_checks_result_filter(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"data": {"affected_items": []}, "error": 0})

    wazuh_api.get("/sca/001/checks/policy1").mock(side_effect=capture)
    await fns["get_sca_policy_checks"](agent_id="001", policy_id="policy1", result="failed")
    assert captured["params"]["result"] == "failed"
