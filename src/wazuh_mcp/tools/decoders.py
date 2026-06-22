from __future__ import annotations

from typing import Optional

from fastmcp import FastMCP

from ..client import WazuhClient


def register(mcp: FastMCP, client: WazuhClient) -> None:

    @mcp.tool()
    async def list_decoders(
        decoder_names: Optional[str] = None,
        status: Optional[str] = None,
        filename: Optional[str] = None,
        relative_dirname: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        select: Optional[str] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
    ) -> dict:
        """
        Lists available Wazuh decoders with optional filters.

        Args:
            decoder_names: Comma-separated decoder names.
            status: Filter by status. Values: 'enabled', 'disabled'.
            filename: XML decoder file name.
            relative_dirname: Relative directory of the decoders.
            limit: Maximum number of results.
            offset: Offset for pagination.
            select: Comma-separated fields to include.
            sort: Field and order (e.g. '+name').
            search: Text search in name and description.

        Returns:
            data.affected_items: Decoders with name, filename, relative_dirname, status, parents.
        """
        params = {k: v for k, v in {
            "decoder_names": decoder_names, "status": status,
            "filename": filename, "relative_dirname": relative_dirname,
            "limit": limit, "offset": offset,
            "select": select, "sort": sort, "search": search,
        }.items() if v is not None}
        return await client.get("/decoders", params=params or None)

    @mcp.tool()
    async def list_decoders_files(
        status: Optional[str] = None,
        relative_dirname: Optional[str] = None,
        filename: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> dict:
        """
        Lists XML decoder files with path and status.

        Args:
            status: Filter by status. Values: 'enabled', 'disabled'.
            relative_dirname: Relative directory of the files.
            filename: File name to search for.
            limit: Maximum number of results.
            offset: Offset for pagination.

        Returns:
            data.affected_items: Decoder files with filename, relative_dirname, status.
        """
        params = {k: v for k, v in {
            "status": status, "relative_dirname": relative_dirname,
            "filename": filename, "limit": limit, "offset": offset,
        }.items() if v is not None}
        return await client.get("/decoders/files", params=params or None)

    @mcp.tool()
    async def get_decoders_file(filename: str, raw: Optional[bool] = None) -> dict:
        """
        Returns the content of a decoder file.

        Args:
            filename: XML file name (e.g. '0005-wazuh_decoders.xml').
            raw: If True, returns raw XML; if False, returns parsed JSON.

        Returns:
            Decoder file content in XML or JSON depending on raw.
        """
        params = {"raw": raw} if raw is not None else None
        return await client.get(f"/decoders/files/{filename}", params=params)

    @mcp.tool()
    async def update_decoders_file(
        filename: str,
        content: str,
        overwrite: Optional[bool] = None,
    ) -> dict:
        """
        Updates or creates a decoder file on the manager.

        CAUTION: Overwrites the decoder. May break log parsing if the syntax is incorrect.
        An analysisd reload or manager restart is required to apply changes.

        Args:
            filename: XML file name (e.g. 'local_decoder.xml').
            content: Full XML content with the new decoders.
            overwrite: If True, allows modifying existing files (required to edit).

        Returns:
            data.affected_items: Confirmation of the file update.
        """
        params = {"overwrite": overwrite} if overwrite is not None else None
        return await client.put(
            f"/decoders/files/{filename}",
            content=content,
            content_type="application/octet-stream",
            params=params,
        )

    @mcp.tool()
    async def delete_decoders_file(filename: str) -> dict:
        """
        Deletes a decoder file from the manager.

        DESTRUCTIVE: Logs that relied on this decoder will no longer be parsed correctly.

        Args:
            filename: XML file name to delete (e.g. 'local_decoder.xml').

        Returns:
            data.affected_items: Confirmation of the deletion.
        """
        return await client.delete(f"/decoders/files/{filename}")

    @mcp.tool()
    async def list_parent_decoders(
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> dict:
        """
        Lists decoders with no parent decoder (entry points of the parse tree).

        Args:
            limit: Maximum number of results.
            offset: Offset for pagination.

        Returns:
            data.affected_items: Root decoders in the parse tree (no parent).
        """
        params = {k: v for k, v in {
            "limit": limit, "offset": offset,
        }.items() if v is not None}
        return await client.get("/decoders/parents", params=params or None)
