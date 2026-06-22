import pytest
import httpx
from fastmcp import FastMCP

from wazuh_mcp.client import WazuhAPIError
from wazuh_mcp.tools import rules

RULE_ITEM = {
    "id": 1002, "level": 2, "status": "enabled",
    "description": "Unknown problem somewhere in the system",
    "groups": ["syslog"], "filename": "0020-syslog_rules.xml",
}
SUCCESS = {
    "data": {"affected_items": [RULE_ITEM], "total_affected_items": 1, "failed_items": []},
    "error": 0,
}


@pytest.fixture
async def fns(mock_client):
    mcp = FastMCP("test")
    rules.register(mcp, mock_client)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


# ── list_rules ────────────────────────────────────────────────────────────────

async def test_list_rules_happy_path(fns, wazuh_api):
    wazuh_api.get("/rules").mock(return_value=httpx.Response(200, json=SUCCESS))
    result = await fns["list_rules"]()
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["id"] == 1002


async def test_list_rules_403(fns, wazuh_api):
    wazuh_api.get("/rules").mock(
        return_value=httpx.Response(403, json={"detail": "Permiso denegado"})
    )
    with pytest.raises(WazuhAPIError) as exc:
        await fns["list_rules"]()
    assert "Permission denied" in str(exc.value)


async def test_list_rules_no_optional_params(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.get("/rules").mock(side_effect=capture)
    await fns["list_rules"]()
    for param in ["status", "group", "level", "filename", "mitre"]:
        assert param not in captured["params"]


# ── list_rules_files ──────────────────────────────────────────────────────────

async def test_list_rules_files_happy_path(fns, wazuh_api):
    payload = {
        "data": {
            "affected_items": [
                {"filename": "0020-syslog_rules.xml",
                 "relative_dirname": "ruleset/rules", "status": "enabled"}
            ],
            "total_affected_items": 1, "failed_items": [],
        },
        "error": 0,
    }
    wazuh_api.get("/rules/files").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["list_rules_files"]()
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["filename"] == "0020-syslog_rules.xml"


async def test_list_rules_files_403(fns, wazuh_api):
    wazuh_api.get("/rules/files").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["list_rules_files"]()


async def test_list_rules_files_no_optional_params(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"data": {"affected_items": []}, "error": 0})

    wazuh_api.get("/rules/files").mock(side_effect=capture)
    await fns["list_rules_files"]()
    assert "status" not in captured["params"]
    assert "filename" not in captured["params"]


# ── delete_rules_file ─────────────────────────────────────────────────────────

async def test_delete_rules_file_happy_path(fns, wazuh_api):
    payload = {"data": {"affected_items": ["local_rules.xml"], "total_affected_items": 1, "failed_items": []}, "error": 0}
    wazuh_api.delete("/rules/files/local_rules.xml").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["delete_rules_file"](filename="local_rules.xml")
    assert result["error"] == 0


async def test_delete_rules_file_403(fns, wazuh_api):
    wazuh_api.delete("/rules/files/local_rules.xml").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["delete_rules_file"](filename="local_rules.xml")
