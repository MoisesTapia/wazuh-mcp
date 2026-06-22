import pytest
import httpx
from fastmcp import FastMCP

from wazuh_mcp.client import WazuhAPIError
from wazuh_mcp.tools import decoders

DECODER_ITEM = {
    "name": "syslog", "filename": "0005-wazuh_decoders.xml",
    "relative_dirname": "ruleset/decoders", "status": "enabled", "parents": [],
}
SUCCESS = {
    "data": {"affected_items": [DECODER_ITEM], "total_affected_items": 1, "failed_items": []},
    "error": 0,
}


@pytest.fixture
async def fns(mock_client):
    mcp = FastMCP("test")
    decoders.register(mcp, mock_client)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


# ── list_decoders ─────────────────────────────────────────────────────────────

async def test_list_decoders_happy_path(fns, wazuh_api):
    wazuh_api.get("/decoders").mock(return_value=httpx.Response(200, json=SUCCESS))
    result = await fns["list_decoders"]()
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["name"] == "syslog"


async def test_list_decoders_403(fns, wazuh_api):
    wazuh_api.get("/decoders").mock(
        return_value=httpx.Response(403, json={"detail": "Permiso denegado"})
    )
    with pytest.raises(WazuhAPIError) as exc:
        await fns["list_decoders"]()
    assert "Permission denied" in str(exc.value)


async def test_list_decoders_no_optional_params(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.get("/decoders").mock(side_effect=capture)
    await fns["list_decoders"]()
    for param in ["decoder_names", "status", "filename"]:
        assert param not in captured["params"]


# ── list_decoders_files ───────────────────────────────────────────────────────

async def test_list_decoders_files_happy_path(fns, wazuh_api):
    payload = {
        "data": {
            "affected_items": [
                {"filename": "0005-wazuh_decoders.xml",
                 "relative_dirname": "ruleset/decoders", "status": "enabled"}
            ],
            "total_affected_items": 1, "failed_items": [],
        },
        "error": 0,
    }
    wazuh_api.get("/decoders/files").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["list_decoders_files"]()
    assert result["error"] == 0


async def test_list_decoders_files_403(fns, wazuh_api):
    wazuh_api.get("/decoders/files").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["list_decoders_files"]()


async def test_list_decoders_files_no_optional_params(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"data": {"affected_items": []}, "error": 0})

    wazuh_api.get("/decoders/files").mock(side_effect=capture)
    await fns["list_decoders_files"]()
    assert "status" not in captured["params"]
    assert "filename" not in captured["params"]


# ── delete_decoders_file ──────────────────────────────────────────────────────

async def test_delete_decoders_file_happy_path(fns, wazuh_api):
    payload = {"data": {"affected_items": ["local_decoder.xml"], "total_affected_items": 1, "failed_items": []}, "error": 0}
    wazuh_api.delete("/decoders/files/local_decoder.xml").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["delete_decoders_file"](filename="local_decoder.xml")
    assert result["error"] == 0


async def test_delete_decoders_file_403(fns, wazuh_api):
    wazuh_api.delete("/decoders/files/local_decoder.xml").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["delete_decoders_file"](filename="local_decoder.xml")


# ── list_parent_decoders ──────────────────────────────────────────────────────

async def test_list_parent_decoders_happy_path(fns, wazuh_api):
    wazuh_api.get("/decoders/parents").mock(return_value=httpx.Response(200, json=SUCCESS))
    result = await fns["list_parent_decoders"]()
    assert result["error"] == 0
