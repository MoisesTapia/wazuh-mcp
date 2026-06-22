import pytest
import httpx
from fastmcp import FastMCP

from wazuh_mcp.client import WazuhAPIError
from wazuh_mcp.tools import mitre

TECHNIQUE_ITEM = {
    "id": "T1059", "name": "Command and Scripting Interpreter",
    "tactics": ["TA0002"], "platforms": ["linux", "windows"],
}
SUCCESS = {
    "data": {"affected_items": [TECHNIQUE_ITEM], "total_affected_items": 1, "failed_items": []},
    "error": 0,
}


@pytest.fixture
async def fns(mock_client):
    mcp = FastMCP("test")
    mitre.register(mcp, mock_client)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


# ── list_mitre_techniques ─────────────────────────────────────────────────────

async def test_list_mitre_techniques_happy_path(fns, wazuh_api):
    wazuh_api.get("/mitre/techniques").mock(return_value=httpx.Response(200, json=SUCCESS))
    result = await fns["list_mitre_techniques"]()
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["id"] == "T1059"


async def test_list_mitre_techniques_403(fns, wazuh_api):
    wazuh_api.get("/mitre/techniques").mock(
        return_value=httpx.Response(403, json={"detail": "Permiso denegado"})
    )
    with pytest.raises(WazuhAPIError) as exc:
        await fns["list_mitre_techniques"]()
    assert "Permission denied" in str(exc.value)


async def test_list_mitre_techniques_no_optional_params(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.get("/mitre/techniques").mock(side_effect=capture)
    await fns["list_mitre_techniques"]()
    for param in ["ids", "phases", "platforms", "search"]:
        assert param not in captured["params"]


# ── list_mitre_tactics ────────────────────────────────────────────────────────

async def test_list_mitre_tactics_happy_path(fns, wazuh_api):
    payload = {
        "data": {
            "affected_items": [{"id": "TA0002", "name": "Execution", "shortname": "execution"}],
            "total_affected_items": 1, "failed_items": [],
        },
        "error": 0,
    }
    wazuh_api.get("/mitre/tactics").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["list_mitre_tactics"]()
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["id"] == "TA0002"


async def test_list_mitre_tactics_403(fns, wazuh_api):
    wazuh_api.get("/mitre/tactics").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["list_mitre_tactics"]()


# ── list_mitre_groups ─────────────────────────────────────────────────────────

async def test_list_mitre_groups_happy_path(fns, wazuh_api):
    payload = {
        "data": {
            "affected_items": [{"id": "G0016", "name": "APT29", "aliases": ["Cozy Bear"]}],
            "total_affected_items": 1, "failed_items": [],
        },
        "error": 0,
    }
    wazuh_api.get("/mitre/groups").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["list_mitre_groups"]()
    assert result["error"] == 0
    assert result["data"]["affected_items"][0]["name"] == "APT29"


async def test_list_mitre_groups_403(fns, wazuh_api):
    wazuh_api.get("/mitre/groups").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["list_mitre_groups"]()


# ── get_mitre_metadata ────────────────────────────────────────────────────────

async def test_get_mitre_metadata_happy_path(fns, wazuh_api):
    payload = {
        "data": {
            "affected_items": [{"version": "v14.1", "date": "2024-01-01"}],
            "total_affected_items": 1, "failed_items": [],
        },
        "error": 0,
    }
    wazuh_api.get("/mitre/metadata").mock(return_value=httpx.Response(200, json=payload))
    result = await fns["get_mitre_metadata"]()
    assert result["error"] == 0
    assert "version" in result["data"]["affected_items"][0]


async def test_get_mitre_metadata_403(fns, wazuh_api):
    wazuh_api.get("/mitre/metadata").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(WazuhAPIError):
        await fns["get_mitre_metadata"]()


async def test_list_mitre_techniques_ids_filter(fns, wazuh_api):
    captured: dict = {}

    def capture(request, route):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json=SUCCESS)

    wazuh_api.get("/mitre/techniques").mock(side_effect=capture)
    await fns["list_mitre_techniques"](ids="T1059,T1078")
    assert captured["params"]["ids"] == "T1059,T1078"
