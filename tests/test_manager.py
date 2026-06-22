import pytest
import httpx
from fastmcp import FastMCP

from wazuh_mcp.client import WazuhAPIError
from wazuh_mcp.tools import manager

DAEMON_STATUS = {"wazuh-analysisd": "running", "wazuh-remoted": "running"}
SUCCESS = {
    "data": {"affected_items": [DAEMON_STATUS], "total_affected_items": 1, "failed_items": []},
    "error": 0,
}


@pytest.fixture
async def fns(mock_client):
    mcp = FastMCP("test")
    manager.register(mcp, mock_client)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


# ── get_manager_status ────────────────────────────────────────────────────────

async def test_get_manager_status_happy_path(fns, wazuh_api):
    wazuh_api.get("/manager/status").mock(return_value=httpx.Response(200, json=SUCCESS))
    result = await fns["get_manager_status"]()
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["wazuh-analysisd"] == "running"


async def test_get_manager_status_403(fns, wazuh_api):
    wazuh_api.get("/manager/status").mock(
        return_value=httpx.Response(403, json={"detail": "Permiso denegado"})
    )
    with pytest.raises(WazuhAPIError) as exc:
        await fns["get_manager_status"]()
    assert "Permission denied" in str(exc.value)


# ── get_manager_configuration ─────────────────────────────────────────────────

async def test_get_manager_configuration_no_params(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.get("/manager/configuration").mock(side_effect=capture)
    await fns["get_manager_configuration"]()
    assert "section" not in captured["params"]
    assert "field" not in captured["params"]


async def test_get_manager_configuration_with_section(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.get("/manager/configuration").mock(side_effect=capture)
    await fns["get_manager_configuration"](section="global")
    assert captured["params"]["section"] == "global"


async def test_get_manager_configuration_403(fns, wazuh_api):
    wazuh_api.get("/manager/configuration").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["get_manager_configuration"]()


# ── get_manager_logs ──────────────────────────────────────────────────────────

async def test_get_manager_logs_happy_path(fns, wazuh_api):
    logs_payload = {
        "data": {
            "affected_items": [
                {"timestamp": "2024-01-01T00:00:00Z", "level": "info",
                 "tag": "wazuh-analysisd", "message": "Started"}
            ],
            "total_affected_items": 1, "failed_items": [],
        },
        "error": 0,
    }
    wazuh_api.get("/manager/logs").mock(return_value=httpx.Response(200, json=logs_payload))
    result = await fns["get_manager_logs"]()
    assert "_wazuh_external_data" in result
    content = result["_wazuh_external_data"]["content"]
    assert content["error"] == 0
    assert len(content["data"]["affected_items"]) == 1


async def test_get_manager_logs_403(fns, wazuh_api):
    wazuh_api.get("/manager/logs").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["get_manager_logs"]()


async def test_get_manager_logs_level_param(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"data": {"affected_items": []}, "error": 0})

    wazuh_api.get("/manager/logs").mock(side_effect=capture)
    await fns["get_manager_logs"](level="error")
    assert captured["params"]["level"] == "error"


# ── restart_manager ───────────────────────────────────────────────────────────

async def test_restart_manager_happy_path(fns, wazuh_api):
    payload = {"data": {"affected_items": [], "total_affected_items": 0, "failed_items": []}, "error": 0}
    wazuh_api.put("/manager/restart").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["restart_manager"]()
    assert result["error"] == 0


async def test_restart_manager_403(fns, wazuh_api):
    wazuh_api.put("/manager/restart").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["restart_manager"]()
