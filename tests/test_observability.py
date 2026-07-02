import asyncio

import pytest
from fastmcp import FastMCP
from unittest.mock import AsyncMock

from wazuh_mcp.api.wazuh_indexer import WazuhIndexerClient
from wazuh_mcp.circuit_breaker import CircuitState
from wazuh_mcp.client import WazuhAPIError
from wazuh_mcp.tools import observability


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_indexer():
    return AsyncMock(spec=WazuhIndexerClient)


@pytest.fixture
async def fns(mock_client, mock_indexer):
    mcp = FastMCP("test")
    observability.register(mcp, mock_client, mock_indexer)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


@pytest.fixture
async def fns_no_indexer(mock_client):
    mcp = FastMCP("test")
    observability.register(mcp, mock_client, None)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


# ── get_mcp_health ────────────────────────────────────────────────────────────

async def test_get_mcp_health_returns_healthy_when_manager_ok(fns, mock_client):
    mock_client.get = AsyncMock(
        return_value={"data": {"api_version": "4.14.5"}, "error": 0}
    )
    result = await fns["get_mcp_health"]()
    assert result["status"] == "healthy"
    assert result["components"]["wazuh_manager"]["status"] == "ok"
    assert result["components"]["wazuh_manager"]["api_version"] == "4.14.5"
    assert "circuit_breaker" in result["components"]["wazuh_manager"]


async def test_get_mcp_health_returns_unhealthy_when_manager_down(fns, mock_client):
    mock_client.get = AsyncMock(side_effect=WazuhAPIError("down", status_code=503))
    result = await fns["get_mcp_health"]()
    assert result["status"] == "unhealthy"
    assert result["components"]["wazuh_manager"]["status"] == "error"


async def test_get_mcp_health_degraded_when_indexer_fails(fns, mock_client, mock_indexer):
    mock_client.get = AsyncMock(
        return_value={"data": {"api_version": "4.14.5"}, "error": 0}
    )
    mock_indexer.get_indices = AsyncMock(side_effect=Exception("indexer down"))
    result = await fns["get_mcp_health"]()
    assert result["status"] == "degraded"
    assert result["components"]["wazuh_manager"]["status"] == "ok"
    assert result["components"]["wazuh_indexer"]["status"] == "error"


async def test_get_mcp_health_without_indexer(fns_no_indexer, mock_client):
    mock_client.get = AsyncMock(
        return_value={"data": {"api_version": "4.14.5"}, "error": 0}
    )
    result = await fns_no_indexer["get_mcp_health"]()
    assert result["components"]["wazuh_indexer"]["status"] == "not_configured"


# ── get_mcp_metrics ───────────────────────────────────────────────────────────

async def test_get_mcp_metrics_does_not_expose_credentials(fns):
    result = await fns["get_mcp_metrics"]()
    config = result["configuration"]
    assert "wazuh_password" not in config
    assert "wazuh_indexer_password" not in config
    assert "wazuh_user" not in config


async def test_get_mcp_metrics_has_circuit_breaker_info(fns):
    result = await fns["get_mcp_metrics"]()
    assert "circuit_breaker" in result
    assert result["circuit_breaker"]["state"] in ["closed", "open", "half_open"]


async def test_uptime_increases_over_time(fns):
    r1 = await fns["get_mcp_metrics"]()
    await asyncio.sleep(0.05)
    r2 = await fns["get_mcp_metrics"]()
    assert r2["uptime_seconds"] >= r1["uptime_seconds"]


# ── reset_circuit_breaker ─────────────────────────────────────────────────────

async def test_reset_circuit_breaker_closes_open_cb(fns, mock_client):
    mock_client._cb._state = CircuitState.OPEN
    result = await fns["reset_circuit_breaker"]()
    assert result["previous_state"] == "open"
    assert result["current_state"] == "closed"
