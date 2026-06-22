from __future__ import annotations

from typing import Optional

from fastmcp import FastMCP

from ..client import WazuhClient
from ..sanitize import wrap_external_content


def register(mcp: FastMCP, client: WazuhClient) -> None:

    @mcp.tool()
    async def get_syscheck_results(
        agent_id: str,
        file: Optional[str] = None,
        type: Optional[str] = None,
        summary: Optional[bool] = None,
        md5: Optional[str] = None,
        sha1: Optional[str] = None,
        sha256: Optional[str] = None,
        date: Optional[str] = None,
        newer_than: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
    ) -> dict:
        """
        Returns FIM (File Integrity Monitoring) results for an agent.

        Args:
            agent_id: Agent ID (e.g. '001').
            file: Filter by file path (e.g. '/etc/passwd').
            type: Element type. Values: 'file', 'registry_key', 'registry_value'.
            summary: If True, returns a per-file summary instead of all events.
            md5: Filter by MD5 hash.
            sha1: Filter by SHA1 hash.
            sha256: Filter by SHA256 hash.
            date: Last modification date (ISO 8601 format).
            newer_than: Filter elements modified after this date.
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order (e.g. '+date').
            search: Text search in paths.
            select: Comma-separated fields to include.

        Returns:
            data.affected_items: Monitored files with hashes, permissions, user, group, date.
        """
        params = {k: v for k, v in {
            "file": file, "type": type, "summary": summary,
            "md5": md5, "sha1": sha1, "sha256": sha256,
            "date": date, "newer_than": newer_than,
            "limit": limit, "offset": offset,
            "sort": sort, "search": search, "select": select,
        }.items() if v is not None}
        result = await client.get(f"/syscheck/{agent_id}", params=params or None)
        return wrap_external_content(result, source=f"wazuh_api/syscheck/{agent_id}")

    @mcp.tool()
    async def get_syscheck_last_scan(agent_id: str) -> dict:
        """
        Returns the date and time of the agent's last and next FIM scan.

        Args:
            agent_id: Agent ID (e.g. '001').

        Returns:
            data.affected_items: start (last scan start) and end (last scan end).
        """
        return await client.get(f"/syscheck/{agent_id}/last_scan")

    @mcp.tool()
    async def clear_syscheck_results(agent_id: str) -> dict:
        """
        Deletes all FIM results for an agent from the database.

        DESTRUCTIVE: Clears the FIM baseline. The next scan will rebuild the baseline from scratch.
        Useful to force a re-baseline after intentional mass changes to the system.

        Args:
            agent_id: Agent ID (e.g. '001').

        Returns:
            data.affected_items: Confirmation of the FIM results cleanup.
        """
        return await client.delete(f"/syscheck/{agent_id}")

    @mcp.tool()
    async def run_syscheck_scan(agents_list: Optional[str] = None) -> dict:
        """
        Triggers an immediate FIM scan on the specified agents.

        Args:
            agents_list: Comma-separated agent IDs. If omitted, scans all agents.

        Returns:
            data.affected_items: List of agents with scan initiated.
        """
        params = {"agents_list": agents_list} if agents_list is not None else None
        return await client.put("/syscheck", params=params)
