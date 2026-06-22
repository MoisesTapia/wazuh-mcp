from __future__ import annotations

from typing import Optional

from fastmcp import FastMCP

from ..client import WazuhClient


def register(mcp: FastMCP, client: WazuhClient) -> None:

    @mcp.tool()
    async def list_groups(
        group_id: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Lists agent groups with name, agent count and configuration.

        Args:
            group_id: Group name to search for.
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order (e.g. '+name').
            search: Text search in group name.
            select: Comma-separated fields to include.
            q: Advanced query filter (e.g. 'count>5').

        Returns:
            data.affected_items: Groups with name, count (number of agents), configSum, mergedSum.
        """
        params = {k: v for k, v in {
            "group_id": group_id, "limit": limit, "offset": offset,
            "sort": sort, "search": search, "select": select, "q": q,
        }.items() if v is not None}
        return await client.get("/groups", params=params or None)

    @mcp.tool()
    async def create_group(group_id: str) -> dict:
        """
        Creates a new empty agent group.

        The group configuration (agent.conf) is assigned later with update_group_config.

        Args:
            group_id: Unique name for the new group.

        Returns:
            data.affected_items: Confirmation with the created group name.
        """
        return await client.post("/groups", json={"group_id": group_id})

    @mcp.tool()
    async def delete_groups(
        groups_list: str,
        q: Optional[str] = None,
    ) -> dict:
        """
        Permanently deletes groups.

        DESTRUCTIVE: Member agents of the deleted groups will have no group assigned.

        Args:
            groups_list: Comma-separated group names.
            q: Additional query filter.

        Returns:
            data.affected_items: List of deleted groups.
            data.failed_items: Groups that could not be deleted.
        """
        params: dict = {"groups_list": groups_list}
        if q is not None:
            params["q"] = q
        return await client.delete("/groups", params=params)

    @mcp.tool()
    async def get_agents_in_group(
        group_id: str,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Lists agents that are members of a group.

        Args:
            group_id: Group name.
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order (e.g. '+name').
            search: Text search.
            select: Comma-separated fields to include.
            q: Advanced query filter.

        Returns:
            data.affected_items: Agents with id, name, ip, status, os, version.
        """
        params = {k: v for k, v in {
            "limit": limit, "offset": offset, "sort": sort,
            "search": search, "select": select, "q": q,
        }.items() if v is not None}
        return await client.get(f"/groups/{group_id}/agents", params=params or None)

    @mcp.tool()
    async def get_group_config(
        group_id: str,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> dict:
        """
        Returns the group's agent.conf configuration in JSON format.

        Args:
            group_id: Group name.
            limit: Maximum number of results.
            offset: Offset for pagination.

        Returns:
            data.affected_items: Group agent.conf configuration in structured JSON format.
        """
        params = {k: v for k, v in {
            "limit": limit, "offset": offset,
        }.items() if v is not None}
        return await client.get(f"/groups/{group_id}/configuration", params=params or None)

    @mcp.tool()
    async def update_group_config(group_id: str, xml_content: str) -> dict:
        """
        Updates the group's agent.conf configuration.

        CAUTION: Overwrites the group's agent.conf.
        Changes propagate to member agents on the next synchronization cycle.

        Args:
            group_id: Group name.
            xml_content: Full XML content of the new agent.conf configuration.

        Returns:
            data.affected_items: Confirmation of the update.
        """
        return await client.put(
            f"/groups/{group_id}/configuration",
            content=xml_content,
            content_type="application/octet-stream",
        )

    @mcp.tool()
    async def list_group_files(
        group_id: str,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
    ) -> dict:
        """
        Lists configuration files in a group.

        Args:
            group_id: Group name.
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Text search in file name.

        Returns:
            data.affected_items: Group files with filename and hash.
        """
        params = {k: v for k, v in {
            "limit": limit, "offset": offset, "sort": sort, "search": search,
        }.items() if v is not None}
        return await client.get(f"/groups/{group_id}/files", params=params or None)

    @mcp.tool()
    async def get_group_file(
        group_id: str,
        file_name: str,
        raw: Optional[bool] = None,
    ) -> dict:
        """
        Returns the content of a group configuration file.

        Args:
            group_id: Group name.
            file_name: File name (e.g. 'agent.conf').
            raw: If True, returns the raw file contents.

        Returns:
            File content in JSON or raw format depending on raw.
        """
        params = {"raw": raw} if raw is not None else None
        return await client.get(f"/groups/{group_id}/files/{file_name}", params=params)
