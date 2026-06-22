from __future__ import annotations

from typing import Optional

from fastmcp import FastMCP

from ..client import WazuhClient
from ..sanitize import wrap_external_content


def register(mcp: FastMCP, client: WazuhClient) -> None:

    @mcp.tool()
    async def get_rootcheck_results(
        agent_id: str,
        pci_dss: Optional[str] = None,
        cis: Optional[str] = None,
        status: Optional[str] = None,
        event: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Lists rootkit check results for an agent.

        Args:
            agent_id: Agent ID with zero-padding (e.g. '001').
            pci_dss: Filter by PCI DSS control (e.g. '1.4').
            cis: Filter by CIS control.
            status: Result status. Values: 'all', 'solved', 'outstanding'.
            event: Filter by event message.
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Free text search.
            select: Comma-separated fields to include.
            q: Advanced query filter.

        Returns:
            data.affected_items: Results with log, date_last, date_first, status.
        """
        params = {k: v for k, v in {
            "pci_dss": pci_dss, "cis": cis, "status": status, "event": event,
            "limit": limit, "offset": offset, "sort": sort,
            "search": search, "select": select, "q": q,
        }.items() if v is not None}
        result = await client.get(f"/rootcheck/{agent_id}", params=params or None)
        return wrap_external_content(result, source=f"wazuh_api/rootcheck/{agent_id}")

    @mcp.tool()
    async def get_rootcheck_last_scan(agent_id: str) -> dict:
        """
        Returns the date of the last rootkit scan for an agent.

        Args:
            agent_id: Agent ID (e.g. '001').

        Returns:
            data.affected_items: Date of the last rootkit scan (start, end).
        """
        return await client.get(f"/rootcheck/{agent_id}/last_scan")

    @mcp.tool()
    async def clear_rootcheck_results(agent_id: str) -> dict:
        """
        Deletes the rootcheck result history for an agent.

        DESTRUCTIVE: Deletes all rootcheck results for the agent.
        This operation cannot be undone.

        Args:
            agent_id: Agent ID (e.g. '001').

        Returns:
            data.affected_items: Confirmation of deletion.
        """
        return await client.delete(f"/rootcheck/{agent_id}")

    @mcp.tool()
    async def run_rootcheck_scan(
        agents_list: Optional[str] = None,
    ) -> dict:
        """
        Triggers a rootkit scan on the specified agents.

        Args:
            agents_list: Comma-separated agent IDs (e.g. '001,002').
                If omitted, runs on all active agents.

        Returns:
            data.affected_items: List of agents where the scan was initiated.
        """
        params = {"agents_list": agents_list} if agents_list is not None else None
        return await client.put("/rootcheck", params=params)
