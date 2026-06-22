from __future__ import annotations

from typing import Any, Optional

from fastmcp import FastMCP

from ..client import WazuhClient


def register(mcp: FastMCP, client: WazuhClient) -> None:

    @mcp.tool()
    async def run_active_response(
        command: str,
        arguments: Optional[list[str]] = None,
        alert: Optional[dict[str, Any]] = None,
        agents_list: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Executes an Active Response script on the specified agents.

        CAUTION: Runs commands directly on agents. Only use with scripts
        previously configured in ossec.conf under <active-response>.

        Args:
            command: Name of the active response script configured on the manager
                (e.g. 'restart-wazuh', 'firewall-drop', 'disable-account').
            arguments: List of additional arguments for the script (e.g. ['-', 'null', '0', '0']).
            alert: Dict with alert data passed to the script. Structure:
                {'rule': {'id': '100001', 'description': '...'}, 'data': {...}}.
            agents_list: Comma-separated agent IDs (e.g. '001,002').
                If omitted, runs on all active agents.
            q: Query filter to select agents.

        Returns:
            data.affected_agents: List of agents where the command was executed.
        """
        body: dict[str, Any] = {"command": command}
        if arguments is not None:
            body["arguments"] = arguments
        if alert is not None:
            body["alert"] = alert
        params = {k: v for k, v in {
            "agents_list": agents_list, "q": q,
        }.items() if v is not None}
        return await client.put(
            "/active-response", json=body, params=params or None
        )
