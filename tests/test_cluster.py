import pytest
import httpx
from fastmcp import FastMCP

from wazuh_mcp.client import WazuhAPIError
from wazuh_mcp.tools import cluster

NODE_ITEM = {
    "name": "node01", "ip": "192.168.1.1", "version": "4.7.0",
    "type": "master", "status": "connected",
}
SUCCESS = {
    "data": {"affected_items": [NODE_ITEM], "total_affected_items": 1, "failed_items": []},
    "error": 0,
}


@pytest.fixture
async def fns(mock_client):
    mcp = FastMCP("test")
    cluster.register(mcp, mock_client)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


# ── get_cluster_status ────────────────────────────────────────────────────────

async def test_get_cluster_status_happy_path(fns, wazuh_api):
    payload = {
        "data": {"affected_items": [{"enabled": "yes", "running": "yes"}],
                 "total_affected_items": 1, "failed_items": []},
        "error": 0,
    }
    wazuh_api.get("/cluster/status").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["get_cluster_status"]()
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["enabled"] == "yes"


async def test_get_cluster_status_403(fns, wazuh_api):
    wazuh_api.get("/cluster/status").mock(
        return_value=httpx.Response(403, json={"detail": "Permiso denegado"})
    )
    with pytest.raises(WazuhAPIError) as exc:
        await fns["get_cluster_status"]()
    assert "Permission denied" in str(exc.value)


# ── get_cluster_nodes ─────────────────────────────────────────────────────────

async def test_get_cluster_nodes_happy_path(fns, wazuh_api):
    wazuh_api.get("/cluster/nodes").mock(return_value=httpx.Response(200, json=SUCCESS))
    result = await fns["get_cluster_nodes"]()
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["name"] == "node01"


async def test_get_cluster_nodes_403(fns, wazuh_api):
    wazuh_api.get("/cluster/nodes").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["get_cluster_nodes"]()


async def test_get_cluster_nodes_type_filter(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.get("/cluster/nodes").mock(side_effect=capture)
    await fns["get_cluster_nodes"](type="master")
    assert captured["params"]["type"] == "master"


# ── get_cluster_healthcheck ───────────────────────────────────────────────────

async def test_get_cluster_healthcheck_happy_path(fns, wazuh_api):
    payload = {
        "data": {
            "affected_items": [
                {"name": "node01", "info": {"last_sync": {"integrity_check": {"date": "2024-01-01"}}}}
            ],
            "total_affected_items": 1, "failed_items": [],
        },
        "error": 0,
    }
    wazuh_api.get("/cluster/healthcheck").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["get_cluster_healthcheck"]()
    assert result["error"] == 0


async def test_get_cluster_healthcheck_403(fns, wazuh_api):
    wazuh_api.get("/cluster/healthcheck").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["get_cluster_healthcheck"]()


# ── restart_cluster ───────────────────────────────────────────────────────────

async def test_restart_cluster_happy_path(fns, wazuh_api):
    payload = {"data": {"affected_items": [{"name": "node01"}], "total_affected_items": 1, "failed_items": []}, "error": 0}
    wazuh_api.put("/cluster/restart").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["restart_cluster"]()
    assert result["error"] == 0


async def test_restart_cluster_403(fns, wazuh_api):
    wazuh_api.put("/cluster/restart").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["restart_cluster"]()


async def test_restart_cluster_no_nodes_list_by_default(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"data": {"affected_items": []}, "error": 0})

    wazuh_api.put("/cluster/restart").mock(side_effect=capture)
    await fns["restart_cluster"]()
    assert "nodes_list" not in captured["params"]
