import pytest
import httpx
from fastmcp import FastMCP

from wazuh_mcp.tools import lists

SUCCESS = {
    "data": {"affected_items": [{"filename": "audit-keys", "path": "/var/ossec/etc/lists/audit-keys"}]},
    "error": 0,
}
EMPTY = {"data": {"affected_items": []}, "error": 0}


@pytest.fixture
async def fns(mock_client):
    mcp = FastMCP("test")
    lists.register(mcp, mock_client)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


async def test_list_cdb_lists_happy_path(fns, wazuh_api):
    wazuh_api.get("/lists").mock(return_value=httpx.Response(200, json=SUCCESS))
    result = await fns["list_cdb_lists"]()
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["filename"] == "audit-keys"


async def test_list_cdb_list_files_happy_path(fns, wazuh_api):
    wazuh_api.get("/lists/files").mock(return_value=httpx.Response(200, json=SUCCESS))
    result = await fns["list_cdb_list_files"]()
    assert result["error"] == 0


async def test_get_cdb_list_file_raw(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"data": "key:value\n", "error": 0})

    wazuh_api.get("/lists/files/audit-keys").mock(side_effect=capture)
    await fns["get_cdb_list_file"](filename="audit-keys", raw=True)
    assert captured["params"]["raw"] == "true"


async def test_get_cdb_list_file_no_none_raw(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"data": [], "error": 0})

    wazuh_api.get("/lists/files/audit-keys").mock(side_effect=capture)
    await fns["get_cdb_list_file"](filename="audit-keys")
    assert "raw" not in captured["params"]


async def test_delete_cdb_list_file(fns, wazuh_api):
    wazuh_api.delete("/lists/files/audit-keys").mock(
        return_value=httpx.Response(200, json=EMPTY)
    )
    result = await fns["delete_cdb_list_file"](filename="audit-keys")
    assert result["error"] == 0
