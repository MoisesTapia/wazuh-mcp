import pytest
import httpx
from fastmcp import FastMCP

from wazuh_mcp.client import WazuhAPIError
from wazuh_mcp.tools import syscheck

FIM_ITEM = {
    "file": "/etc/passwd", "type": "file",
    "mtime": "2024-01-01T00:00:00Z", "md5": "abc123", "sha1": "def456",
    "perm": "-rw-r--r--", "uname": "root", "gname": "root",
}
SUCCESS = {
    "data": {"affected_items": [FIM_ITEM], "total_affected_items": 1, "failed_items": []},
    "error": 0,
}


@pytest.fixture
async def fns(mock_client):
    mcp = FastMCP("test")
    syscheck.register(mcp, mock_client)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


# ── get_syscheck_results ──────────────────────────────────────────────────────

async def test_get_syscheck_results_happy_path(fns, wazuh_api):
    wazuh_api.get("/syscheck/001").mock(return_value=httpx.Response(200, json=SUCCESS))
    result = await fns["get_syscheck_results"](agent_id="001")
    assert "_wazuh_external_data" in result
    content = result["_wazuh_external_data"]["content"]
    assert content["error"] == 0
    assert content["data"]["affected_items"][0]["file"] == "/etc/passwd"


async def test_get_syscheck_results_403(fns, wazuh_api):
    wazuh_api.get("/syscheck/001").mock(
        return_value=httpx.Response(403, json={"detail": "Permiso denegado"})
    )
    with pytest.raises(WazuhAPIError) as exc:
        await fns["get_syscheck_results"](agent_id="001")
    assert "Permission denied" in str(exc.value)


async def test_get_syscheck_results_no_optional_params(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.get("/syscheck/001").mock(side_effect=capture)
    await fns["get_syscheck_results"](agent_id="001")
    for param in ["file", "type", "md5", "sha1", "sha256"]:
        assert param not in captured["params"]


# ── get_syscheck_last_scan ────────────────────────────────────────────────────

async def test_get_syscheck_last_scan_happy_path(fns, wazuh_api):
    payload = {
        "data": {
            "affected_items": [{"start": "2024-01-01T00:00:00Z", "end": "2024-01-01T00:05:00Z"}],
            "total_affected_items": 1, "failed_items": [],
        },
        "error": 0,
    }
    wazuh_api.get("/syscheck/001/last_scan").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["get_syscheck_last_scan"](agent_id="001")
    assert result["error"] == 0
    assert "start" in result["data"]["affected_items"][0]


async def test_get_syscheck_last_scan_403(fns, wazuh_api):
    wazuh_api.get("/syscheck/001/last_scan").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["get_syscheck_last_scan"](agent_id="001")


# ── clear_syscheck_results ────────────────────────────────────────────────────

async def test_clear_syscheck_results_happy_path(fns, wazuh_api):
    payload = {"data": {"affected_items": ["001"], "total_affected_items": 1, "failed_items": []}, "error": 0}
    wazuh_api.delete("/syscheck/001").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["clear_syscheck_results"](agent_id="001")
    assert result["error"] == 0


async def test_clear_syscheck_results_403(fns, wazuh_api):
    wazuh_api.delete("/syscheck/001").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["clear_syscheck_results"](agent_id="001")


# ── run_syscheck_scan ─────────────────────────────────────────────────────────

async def test_run_syscheck_scan_happy_path(fns, wazuh_api):
    payload = {"data": {"affected_items": ["001"], "total_affected_items": 1, "failed_items": []}, "error": 0}
    wazuh_api.put("/syscheck").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["run_syscheck_scan"]()
    assert result["error"] == 0


async def test_run_syscheck_scan_403(fns, wazuh_api):
    wazuh_api.put("/syscheck").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["run_syscheck_scan"]()


async def test_run_syscheck_scan_agents_list_param(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"data": {"affected_items": []}, "error": 0})

    wazuh_api.put("/syscheck").mock(side_effect=capture)
    await fns["run_syscheck_scan"](agents_list="001,002")
    assert captured["params"]["agents_list"] == "001,002"
