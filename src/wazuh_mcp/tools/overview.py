from __future__ import annotations

from fastmcp import FastMCP

from ..client import WazuhClient


def register(mcp: FastMCP, client: WazuhClient) -> None:

    @mcp.tool()
    async def get_agents_overview() -> dict:
        """
        Returns an executive summary of all Wazuh agents.

        Equivalent to calling several /agents/summary/* endpoints in a single request.
        Ideal for dashboards and general infrastructure status views.

        Returns:
            data with counts by: status (active, disconnected, pending,
                never_connected), OS (platform, version), Wazuh version,
                group and cluster node.
        """
        return await client.get("/overview/agents")
