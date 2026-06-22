from __future__ import annotations

from typing import Optional

from fastmcp import FastMCP

from ..client import WazuhClient


def register(mcp: FastMCP, client: WazuhClient) -> None:

    @mcp.tool()
    async def list_cdb_lists(
        filename: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Lists available CDB (Constant Database) lists in Wazuh.

        Args:
            filename: Filter by list file name.
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Free text search.
            select: Comma-separated fields to include.
            q: Advanced query filter.

        Returns:
            data.affected_items: Lists with filename, path, relative_dirname.
        """
        params = {k: v for k, v in {
            "filename": filename, "limit": limit, "offset": offset,
            "sort": sort, "search": search, "select": select, "q": q,
        }.items() if v is not None}
        return await client.get("/lists", params=params or None)

    @mcp.tool()
    async def list_cdb_list_files(
        filename: Optional[str] = None,
        relative_dirname: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
    ) -> dict:
        """
        Lists CDB list files with their path and status.

        Args:
            filename: Filter by file name.
            relative_dirname: Filter by relative directory.
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Free text search.

        Returns:
            data.affected_items: Files with filename, relative_dirname, status.
        """
        params = {k: v for k, v in {
            "filename": filename, "relative_dirname": relative_dirname,
            "limit": limit, "offset": offset, "sort": sort, "search": search,
        }.items() if v is not None}
        return await client.get("/lists/files", params=params or None)

    @mcp.tool()
    async def get_cdb_list_file(
        filename: str,
        raw: Optional[bool] = None,
    ) -> dict:
        """
        Returns the content of a CDB list file.

        Args:
            filename: List file name (e.g. 'audit-keys').
            raw: If True, returns raw content (key:value per line).
                If False (default), returns JSON with a list of {key, value}.

        Returns:
            CDB list content in raw or JSON format depending on raw.
        """
        params = {"raw": raw} if raw is not None else None
        return await client.get(f"/lists/files/{filename}", params=params)

    @mcp.tool()
    async def update_cdb_list_file(
        filename: str,
        content: str,
        overwrite: Optional[bool] = None,
    ) -> dict:
        """
        Updates the content of a CDB list file.

        CAUTION: Overwrites the existing CDB list.
        Rules that reference this list will be immediately affected.

        Args:
            filename: Name of the list file to update (e.g. 'audit-keys').
            content: Plain text content in "key:value" format per line.
            overwrite: If True (required to modify an existing list), allows overwriting.

        Returns:
            data.affected_items: Confirmation of the update.
        """
        params = {"overwrite": overwrite} if overwrite is not None else None
        return await client.put(
            f"/lists/files/{filename}",
            content=content,
            content_type="application/octet-stream",
            params=params,
        )

    @mcp.tool()
    async def delete_cdb_list_file(filename: str) -> dict:
        """
        Deletes a CDB list file.

        DESTRUCTIVE: Permanently deletes the CDB list.
        Rules that reference it will stop working correctly.

        Args:
            filename: Name of the list file to delete.

        Returns:
            data.affected_items: Confirmation of the deletion.
        """
        return await client.delete(f"/lists/files/{filename}")
