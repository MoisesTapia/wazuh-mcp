import pytest
import httpx
from fastmcp import FastMCP

from wazuh_mcp.client import WazuhAPIError
from wazuh_mcp.tools import syscollector

SUCCESS = {
    "data": {"affected_items": [{}], "total_affected_items": 1, "failed_items": []},
    "error": 0,
}


@pytest.fixture
async def fns(mock_client):
    mcp = FastMCP("test")
    syscollector.register(mcp, mock_client)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


# ── get_agent_hardware ────────────────────────────────────────────────────────

async def test_get_agent_hardware_happy_path(fns, wazuh_api):
    payload = {
        "data": {
            "affected_items": [{"cpu": {"name": "Intel", "cores": 4}, "ram": {"total": 8192}}],
            "total_affected_items": 1, "failed_items": [],
        },
        "error": 0,
    }
    wazuh_api.get("/syscollector/001/hardware").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["get_agent_hardware"](agent_id="001")
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["cpu"]["cores"] == 4


async def test_get_agent_hardware_403(fns, wazuh_api):
    wazuh_api.get("/syscollector/001/hardware").mock(
        return_value=httpx.Response(403, json={"detail": "Permiso denegado"})
    )
    with pytest.raises(WazuhAPIError) as exc:
        await fns["get_agent_hardware"](agent_id="001")
    assert "Permission denied" in str(exc.value)


async def test_get_agent_hardware_no_optional_params(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.get("/syscollector/001/hardware").mock(side_effect=capture)
    await fns["get_agent_hardware"](agent_id="001")
    assert "select" not in captured["params"]


# ── get_agent_packages ────────────────────────────────────────────────────────

async def test_get_agent_packages_happy_path(fns, wazuh_api):
    payload = {
        "data": {
            "affected_items": [
                {"name": "openssl", "version": "1.1.1k", "vendor": "Ubuntu", "architecture": "amd64"}
            ],
            "total_affected_items": 1, "failed_items": [],
        },
        "error": 0,
    }
    wazuh_api.get("/syscollector/001/packages").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["get_agent_packages"](agent_id="001")
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["name"] == "openssl"


async def test_get_agent_packages_403(fns, wazuh_api):
    wazuh_api.get("/syscollector/001/packages").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["get_agent_packages"](agent_id="001")


async def test_get_agent_packages_name_filter(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.get("/syscollector/001/packages").mock(side_effect=capture)
    await fns["get_agent_packages"](agent_id="001", name="openssl")
    assert captured["params"]["name"] == "openssl"


# ── get_agent_ports ───────────────────────────────────────────────────────────

async def test_get_agent_ports_happy_path(fns, wazuh_api):
    payload = {
        "data": {
            "affected_items": [
                {"protocol": "tcp", "local_ip": "0.0.0.0", "local_port": 22, "state": "listening"}
            ],
            "total_affected_items": 1, "failed_items": [],
        },
        "error": 0,
    }
    wazuh_api.get("/syscollector/001/ports").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["get_agent_ports"](agent_id="001")
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["local_port"] == 22


async def test_get_agent_ports_403(fns, wazuh_api):
    wazuh_api.get("/syscollector/001/ports").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["get_agent_ports"](agent_id="001")


async def test_get_agent_ports_protocol_filter(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.get("/syscollector/001/ports").mock(side_effect=capture)
    await fns["get_agent_ports"](agent_id="001", protocol="tcp")
    assert captured["params"]["protocol"] == "tcp"


# ── get_agent_os ──────────────────────────────────────────────────────────────

async def test_get_agent_os_happy_path(fns, wazuh_api):
    payload = {
        "data": {
            "affected_items": [
                {"name": "Ubuntu", "version": "22.04", "kernel": "5.15.0"}
            ],
            "total_affected_items": 1, "failed_items": [],
        },
        "error": 0,
    }
    wazuh_api.get("/syscollector/001/os").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["get_agent_os"](agent_id="001")
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["name"] == "Ubuntu"


async def test_get_agent_os_403(fns, wazuh_api):
    wazuh_api.get("/syscollector/001/os").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["get_agent_os"](agent_id="001")
