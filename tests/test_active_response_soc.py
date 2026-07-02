import json
import logging

import httpx
import pytest
from fastmcp import FastMCP

from wazuh_mcp.tools import active_response_soc

SUCCESS = {
    "data": {"affected_items": ["001"], "total_affected_items": 1, "total_failed_items": 0},
    "error": 0,
}


@pytest.fixture
async def fns(mock_client):
    mcp = FastMCP("test")
    active_response_soc.register(mcp, mock_client)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


def _capture_put_body(rx):
    captured: dict = {}

    def capture(request, route):
        captured["body"] = json.loads(request.content)
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    rx.put("/active-response").mock(side_effect=capture)
    return captured


# ── Action tools ──────────────────────────────────────────────────────────────


async def test_block_ip_validates_ip_address(fns, wazuh_api):
    put_route = wazuh_api.put("/active-response").mock(
        return_value=httpx.Response(200, json=SUCCESS)
    )
    result = await fns["wazuh_block_ip"](agent_ids=["001"], ip_address="not-an-ip")
    assert "error" in result
    assert "IP inválida" in result["error"]
    assert put_route.call_count == 0


async def test_block_ip_calls_active_response(fns, wazuh_api):
    captured = _capture_put_body(wazuh_api)
    result = await fns["wazuh_block_ip"](agent_ids=["001", "002"], ip_address="10.0.1.45")
    assert captured["body"]["command"] == "firewall-drop"
    assert captured["body"]["alert"]["data"]["srcip"] == "10.0.1.45"
    assert result["blocked_ip"] == "10.0.1.45"


async def test_block_ip_emits_audit_log(fns, wazuh_api, caplog):
    wazuh_api.put("/active-response").mock(return_value=httpx.Response(200, json=SUCCESS))
    with caplog.at_level(logging.WARNING, logger="wazuh_mcp.tools.active_response_soc"):
        await fns["wazuh_block_ip"](agent_ids=["001"], ip_address="192.168.1.1")
    assert "AUDIT:" in caplog.text
    assert "block_ip" in caplog.text


async def test_unblock_ip_uses_bang_prefix(fns, wazuh_api):
    captured = _capture_put_body(wazuh_api)
    await fns["wazuh_unblock_ip"](agent_ids=["001"], ip_address="10.0.1.45")
    assert captured["body"]["command"] == "!firewall-drop"


async def test_kill_process_sanitizes_command(fns, wazuh_api):
    put_route = wazuh_api.put("/active-response").mock(
        return_value=httpx.Response(200, json=SUCCESS)
    )
    result = await fns["kill_process"](agent_id="001", process_name="malware; rm -rf /")
    assert "error" in result
    assert "caracteres inválidos" in result["error"]
    assert put_route.call_count == 0


async def test_kill_process_valid_name(fns, wazuh_api):
    captured = _capture_put_body(wazuh_api)
    await fns["kill_process"](agent_id="001", process_name="malware-process", pid=1234)
    assert captured["body"]["command"] == "kill-process"
    assert "1234" in captured["body"]["arguments"]


async def test_run_custom_ar_sanitizes_command(fns, wazuh_api):
    put_route = wazuh_api.put("/active-response").mock(
        return_value=httpx.Response(200, json=SUCCESS)
    )
    result = await fns["run_custom_ar"](agent_ids=["001"], command="bad command; ls")
    assert "error" in result
    assert put_route.call_count == 0


async def test_run_custom_ar_valid_command(fns, wazuh_api):
    captured = _capture_put_body(wazuh_api)
    await fns["run_custom_ar"](agent_ids=["001"], command="my-custom-script", arguments=["arg1"])
    assert captured["body"]["command"] == "my-custom-script"


async def test_add_ip_to_cdb_adds_new_entry(mock_client):
    mcp = FastMCP("test")
    active_response_soc.register(mcp, mock_client)

    async def fake_get(path, **kwargs):
        return {"data": {"affected_items": [{"filename": "blacklist", "items": []}]}}

    put_calls: dict = {}

    async def fake_put(path, **kwargs):
        put_calls["path"] = path
        put_calls["content"] = kwargs.get("content")
        return {"error": 0}

    mock_client.get = fake_get
    mock_client.put = fake_put
    tools = await mcp.list_tools()
    fn = {t.name: (await mcp.local_provider.get_tool(t.name)).fn for t in tools}
    result = await fn["wazuh_add_ip_to_cdb"](list_name="blacklist", ip_address="1.2.3.4")
    assert result["action"] == "added"
    assert "1.2.3.4:blocked" in put_calls["content"]


async def test_add_ip_to_cdb_skips_if_exists(mock_client):
    mcp = FastMCP("test")
    active_response_soc.register(mcp, mock_client)

    async def fake_get(path, **kwargs):
        return {
            "data": {
                "affected_items": [
                    {"filename": "blacklist", "items": [{"key": "1.2.3.4", "value": "blocked"}]}
                ]
            }
        }

    put_calls: dict = {"count": 0}

    async def fake_put(path, **kwargs):
        put_calls["count"] += 1
        return {"error": 0}

    mock_client.get = fake_get
    mock_client.put = fake_put
    tools = await mcp.list_tools()
    fn = {t.name: (await mcp.local_provider.get_tool(t.name)).fn for t in tools}
    result = await fn["wazuh_add_ip_to_cdb"](list_name="blacklist", ip_address="1.2.3.4")
    assert result["action"] == "already_exists"
    assert put_calls["count"] == 0


# ── Verification tools ───────────────────────────────────────────────────────


async def test_check_agent_connectivity_returns_status(mock_client):
    mcp = FastMCP("test")
    active_response_soc.register(mcp, mock_client)

    async def fake_get(path, **kwargs):
        if path == "/agents":
            return {
                "data": {
                    "affected_items": [
                        {"id": "001", "status": "active", "lastKeepAlive": "2024-01-01T00:00:00Z"}
                    ]
                }
            }
        return {"error": 0}

    mock_client.get = fake_get
    tools = await mcp.list_tools()
    fn = {t.name: (await mcp.local_provider.get_tool(t.name)).fn for t in tools}
    result = await fn["check_agent_connectivity"](agent_id="001")
    assert result["status"] == "active"
    assert result["is_isolated"] in (None, False)


async def test_verify_process_killed_process_gone(mock_client):
    mcp = FastMCP("test")
    active_response_soc.register(mcp, mock_client)

    async def fake_get(path, **kwargs):
        return {"data": {"affected_items": []}}

    mock_client.get = fake_get
    tools = await mcp.list_tools()
    fn = {t.name: (await mcp.local_provider.get_tool(t.name)).fn for t in tools}
    result = await fn["verify_process_killed"](agent_id="001", process_name="malware")
    assert result["is_running"] is False
    assert result["matching_pids"] == []


async def test_verify_process_killed_process_still_running(mock_client):
    mcp = FastMCP("test")
    active_response_soc.register(mcp, mock_client)

    async def fake_get(path, **kwargs):
        return {"data": {"affected_items": [{"name": "malware", "pid": 1234}]}}

    mock_client.get = fake_get
    tools = await mcp.list_tools()
    fn = {t.name: (await mcp.local_provider.get_tool(t.name)).fn for t in tools}
    result = await fn["verify_process_killed"](agent_id="001", process_name="malware")
    assert result["is_running"] is True
    assert 1234 in result["matching_pids"]
