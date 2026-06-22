from __future__ import annotations

from typing import Optional

from fastmcp import FastMCP

from ..client import WazuhClient


def register(mcp: FastMCP, client: WazuhClient) -> None:

    @mcp.tool()
    async def list_mitre_techniques(
        ids: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        q: Optional[str] = None,
        phases: Optional[str] = None,
        platforms: Optional[str] = None,
    ) -> dict:
        """
        Lists MITRE ATT&CK techniques with ID, name, tactics and platforms.

        Args:
            ids: Comma-separated technique IDs (e.g. 'T1059,T1078').
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order (e.g. '+external_id').
            search: Text search in name and description.
            select: Comma-separated fields to include.
            q: Advanced query filter.
            phases: Filter by tactic phase (e.g. 'execution,persistence').
            platforms: Filter by platform (e.g. 'windows,linux').

        Returns:
            data.affected_items: Techniques with external_id (T1059), name, tactics, platforms, references.
        """
        params = {k: v for k, v in {
            "ids": ids, "limit": limit, "offset": offset,
            "sort": sort, "search": search, "select": select,
            "q": q, "phases": phases, "platforms": platforms,
        }.items() if v is not None}
        return await client.get("/mitre/techniques", params=params or None)

    @mcp.tool()
    async def list_mitre_tactics(
        ids: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Lists MITRE ATT&CK tactics (e.g. TA0001 Initial Access, TA0002 Execution).

        Args:
            ids: Comma-separated tactic IDs (e.g. 'TA0001,TA0002').
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Text search in name and description.
            select: Comma-separated fields to include.
            q: Advanced query filter.

        Returns:
            data.affected_items: Tactics with external_id (TA0001), name, shortname, techniques.
        """
        params = {k: v for k, v in {
            "ids": ids, "limit": limit, "offset": offset,
            "sort": sort, "search": search, "select": select, "q": q,
        }.items() if v is not None}
        return await client.get("/mitre/tactics", params=params or None)

    @mcp.tool()
    async def list_mitre_groups(
        ids: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Lists known threat groups (APTs) with their techniques and aliases.

        Args:
            ids: Comma-separated group IDs (e.g. 'G0001,G0016').
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Text search in name and aliases.
            select: Comma-separated fields to include.
            q: Advanced query filter.

        Returns:
            data.affected_items: Groups with external_id (G0001), name, aliases, techniques, software.
        """
        params = {k: v for k, v in {
            "ids": ids, "limit": limit, "offset": offset,
            "sort": sort, "search": search, "select": select, "q": q,
        }.items() if v is not None}
        return await client.get("/mitre/groups", params=params or None)

    @mcp.tool()
    async def list_mitre_software(
        ids: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Lists malware and attack tools with their techniques and associated groups.

        Args:
            ids: Comma-separated software IDs (e.g. 'S0002,S0008').
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Text search in name and description.
            select: Comma-separated fields to include.
            q: Advanced query filter.

        Returns:
            data.affected_items: Software with external_id (S0002), name, type, techniques, groups.
        """
        params = {k: v for k, v in {
            "ids": ids, "limit": limit, "offset": offset,
            "sort": sort, "search": search, "select": select, "q": q,
        }.items() if v is not None}
        return await client.get("/mitre/software", params=params or None)

    @mcp.tool()
    async def list_mitre_mitigations(
        ids: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Lists MITRE-recommended mitigations to counter ATT&CK techniques.

        Args:
            ids: Comma-separated mitigation IDs (e.g. 'M1049,M1054').
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Text search in name and description.
            select: Comma-separated fields to include.
            q: Advanced query filter.

        Returns:
            data.affected_items: Mitigations with external_id (M1049), name, description, techniques.
        """
        params = {k: v for k, v in {
            "ids": ids, "limit": limit, "offset": offset,
            "sort": sort, "search": search, "select": select, "q": q,
        }.items() if v is not None}
        return await client.get("/mitre/mitigations", params=params or None)

    @mcp.tool()
    async def list_mitre_references(
        ids: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Lists external references linked to MITRE ATT&CK techniques.

        Args:
            ids: Comma-separated reference IDs.
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Text search in URL and description.
            select: Comma-separated fields to include.
            q: Advanced query filter.

        Returns:
            data.affected_items: References with source_name, url, description (papers, blogs, CVEs).
        """
        params = {k: v for k, v in {
            "ids": ids, "limit": limit, "offset": offset,
            "sort": sort, "search": search, "select": select, "q": q,
        }.items() if v is not None}
        return await client.get("/mitre/references", params=params or None)

    @mcp.tool()
    async def get_mitre_metadata() -> dict:
        """
        Returns metadata for the MITRE ATT&CK database loaded in Wazuh.

        Returns:
            data.affected_items: ATT&CK version, last update date and statistics.
        """
        return await client.get("/mitre/metadata")
