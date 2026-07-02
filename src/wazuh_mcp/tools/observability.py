"""
Tools de observabilidad del servidor MCP.

Expone el estado interno tanto como tools MCP (para que el LLM pueda
diagnosticar problemas en modo stdio) como rutas HTTP reales /health y
/metrics (para que el HEALTHCHECK de Docker, que ya hace curl sobre
esas rutas, tenga algo que responder cuando el transporte es HTTP).
"""
from __future__ import annotations

import time
import sys
import platform

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

from ..client import WazuhClient
from ..api import WazuhIndexerClient

# Timestamp de inicio del servidor (para uptime)
_START_TIME = time.monotonic()


def register(
    mcp: FastMCP,
    client: WazuhClient,
    indexer: WazuhIndexerClient | None = None,
) -> None:

    async def _health() -> dict:
        uptime_s = round(time.monotonic() - _START_TIME, 1)
        components: dict = {}
        overall = "healthy"

        # Wazuh Manager
        try:
            resp = await client.get("/")
            api_version = resp.get("data", {}).get("api_version", "unknown")
            components["wazuh_manager"] = {
                "status": "ok",
                "api_version": api_version,
                "circuit_breaker": client.circuit_breaker.get_status(),
            }
        except Exception as exc:
            components["wazuh_manager"] = {
                "status": "error",
                "error": str(exc),
                "circuit_breaker": client.circuit_breaker.get_status(),
            }
            overall = "unhealthy"

        # Wazuh Indexer (opcional)
        if indexer is not None:
            try:
                indices = await indexer.get_indices("wazuh-alerts-*")
                components["wazuh_indexer"] = {
                    "status": "ok",
                    "alert_indices": len(indices),
                }
            except Exception as exc:
                components["wazuh_indexer"] = {
                    "status": "error",
                    "error": str(exc),
                }
                if overall == "healthy":
                    overall = "degraded"
        else:
            components["wazuh_indexer"] = {
                "status": "not_configured",
                "note": "Anade WAZUH_INDEXER_HOST para habilitar",
            }

        return {
            "status": overall,
            "uptime_seconds": uptime_s,
            "python_version": sys.version.split()[0],
            "platform": platform.system(),
            "components": components,
        }

    async def _metrics() -> dict:
        cb_status = client.circuit_breaker.get_status()

        config_safe = {
            "wazuh_host": client._settings.wazuh_host,
            "wazuh_port": client._settings.wazuh_port,
            "wazuh_verify_ssl": client._settings.wazuh_verify_ssl,
            "jwt_refresh_margin": client._settings.jwt_refresh_margin,
            "request_timeout": client._settings.request_timeout,
            "max_retries": client._settings.max_retries,
            "indexer_configured": client._settings.indexer_configured,
        }

        return {
            "uptime_seconds": round(time.monotonic() - _START_TIME, 1),
            "circuit_breaker": cb_status,
            "configuration": config_safe,
        }

    @mcp.tool()
    async def get_mcp_health() -> dict:
        """
        Checks the health status of the MCP server and its connections.

        Verifies:
          - Connectivity with the Wazuh Manager (port 55000)
          - Connectivity with the Wazuh Indexer if configured (port 9200)
          - The Manager circuit breaker state
          - MCP server uptime

        Returns:
            dict with status "healthy"|"degraded"|"unhealthy" and details
            for each component. Use before critical operations to confirm
            the environment is ready.
        """
        return await _health()

    @mcp.tool()
    async def get_mcp_metrics() -> dict:
        """
        Returns usage metrics for the MCP server.

        Includes circuit breaker statistics and the active configuration
        (without credentials).

        Useful for monitoring server behavior in production or
        diagnosing connectivity issues.
        """
        return await _metrics()

    @mcp.tool()
    async def reset_circuit_breaker() -> dict:
        """
        CAUTION: Resets the Wazuh Manager circuit breaker to CLOSED state.

        Only use this once you are sure the Wazuh Manager is reachable
        again. An OPEN circuit breaker means there were 5+ consecutive
        connectivity failures.

        After resetting, the next request will test the connection again.
        If it fails, the failure counter starts incrementing from zero.
        """
        old_state = client.circuit_breaker.state.value
        client.circuit_breaker.reset()
        return {
            "previous_state": old_state,
            "current_state": client.circuit_breaker.state.value,
            "message": "Circuit breaker reseteado. La proxima request probara la conexion.",
        }

    # ── Rutas HTTP reales (solo activas cuando el transporte es HTTP) ──────────
    # El Dockerfile y docker-compose.yml ya hacen `curl http://localhost:8000/health`
    # como HEALTHCHECK, asi que estas rutas deben existir para que no fallen.

    @mcp.custom_route("/health", methods=["GET"])
    async def health_route(request: Request) -> JSONResponse:
        result = await _health()
        status_code = 200 if result["status"] in ("healthy", "degraded") else 503
        return JSONResponse(result, status_code=status_code)

    @mcp.custom_route("/metrics", methods=["GET"])
    async def metrics_route(request: Request) -> JSONResponse:
        return JSONResponse(await _metrics())
