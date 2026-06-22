import pytest
import httpx
from fastmcp import FastMCP

from wazuh_mcp.tools import logtest

LOGTEST_RESULT = {
    "data": {
        "token": "abc123",
        "messages": [],
        "output": {
            "rule": {"id": "5710", "description": "SSH failed login"},
            "decoder": {"name": "sshd"},
        },
    },
    "error": 0,
}


@pytest.fixture
async def fns(mock_client):
    mcp = FastMCP("test")
    logtest.register(mcp, mock_client)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


async def test_run_logtest_happy_path(fns, wazuh_api):
    wazuh_api.put("/logtest").mock(return_value=httpx.Response(200, json=LOGTEST_RESULT))
    result = await fns["run_logtest"](
        event="Dec 25 10:00:00 host sshd: Failed password",
        log_format="syslog",
        location="/var/log/auth.log",
    )
    assert "_wazuh_external_data" in result
    content = result["_wazuh_external_data"]["content"]
    assert content["error"] == 0
    assert content["data"]["token"] == "abc123"
    assert content["data"]["output"]["rule"]["id"] == "5710"


async def test_run_logtest_with_token(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        import json
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=LOGTEST_RESULT)

    wazuh_api.put("/logtest").mock(side_effect=capture)
    await fns["run_logtest"](
        event="test log",
        log_format="syslog",
        location="/var/log/syslog",
        token="existing-token",
    )
    assert captured["body"]["token"] == "existing-token"


async def test_run_logtest_no_token_by_default(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        import json
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=LOGTEST_RESULT)

    wazuh_api.put("/logtest").mock(side_effect=capture)
    await fns["run_logtest"](
        event="test log",
        log_format="json",
        location="/var/log/test",
    )
    assert "token" not in captured["body"]


async def test_end_logtest_session(fns, wazuh_api):
    wazuh_api.delete("/logtest/sessions/abc123").mock(
        return_value=httpx.Response(200, json={"data": {}, "error": 0})
    )
    result = await fns["end_logtest_session"](token="abc123")
    assert result["error"] == 0
