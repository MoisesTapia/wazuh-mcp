import pytest
import httpx
from fastmcp import FastMCP

from wazuh_mcp.tools import events

SUCCESS = {"data": {"affected_items": 2, "failed_items": []}, "error": 0}


@pytest.fixture
async def fns(mock_client):
    mcp = FastMCP("test")
    events.register(mcp, mock_client)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


async def test_ingest_events_happy_path(fns, wazuh_api):
    wazuh_api.post("/events").mock(return_value=httpx.Response(200, json=SUCCESS))
    result = await fns["ingest_events"](
        events=[{"log": "Dec 25 10:00:00 host sshd: test"}, {"log": "another log"}]
    )
    assert "_wazuh_external_data" in result
    content = result["_wazuh_external_data"]["content"]
    assert content["error"] == 0
    assert content["data"]["affected_items"] == 2


async def test_ingest_events_sends_list(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        import json
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.post("/events").mock(side_effect=capture)
    payload = [{"log": "test event 1"}, {"log": "test event 2"}]
    await fns["ingest_events"](events=payload)
    assert captured["body"]["events"] == payload


async def test_ingest_events_single_item(fns, wazuh_api):
    single_success = {"data": {"affected_items": 1, "failed_items": []}, "error": 0}
    wazuh_api.post("/events").mock(return_value=httpx.Response(200, json=single_success))
    result = await fns["ingest_events"](events=[{"log": "single log"}])
    assert result["_wazuh_external_data"]["content"]["data"]["affected_items"] == 1
