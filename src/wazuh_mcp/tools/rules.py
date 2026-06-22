from __future__ import annotations

from typing import Optional

from fastmcp import FastMCP

from ..client import WazuhClient


def register(mcp: FastMCP, client: WazuhClient) -> None:

    @mcp.tool()
    async def list_rules(
        rule_ids: Optional[str] = None,
        status: Optional[str] = None,
        group: Optional[str] = None,
        level: Optional[int] = None,
        filename: Optional[str] = None,
        relative_dirname: Optional[str] = None,
        pci_dss: Optional[str] = None,
        gdpr: Optional[str] = None,
        gpg13: Optional[str] = None,
        hipaa: Optional[str] = None,
        nist_800_53: Optional[str] = None,
        tsc: Optional[str] = None,
        mitre: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        select: Optional[str] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
    ) -> dict:
        """
        Lists Wazuh detection rules with advanced filters.

        Args:
            rule_ids: Comma-separated rule IDs.
            status: Filter by status. Values: 'enabled', 'disabled'.
            group: Rule group name (e.g. 'syslog', 'authentication').
            level: Severity level (0-16). 0=info, 7=medium, 12=high, 15=critical.
            filename: XML rules file name.
            relative_dirname: Relative directory of the rules.
            pci_dss: PCI DSS requirement (e.g. '10.2.4').
            gdpr: GDPR article (e.g. 'IV_35.7.d').
            gpg13: GPG13 control (e.g. '7.1').
            hipaa: HIPAA control (e.g. '164.312.b').
            nist_800_53: NIST 800-53 control (e.g. 'AU-14').
            tsc: TSC control (e.g. 'CC6.1').
            mitre: MITRE ATT&CK technique ID (e.g. 'T1059').
            limit: Maximum number of results.
            offset: Offset for pagination.
            select: Comma-separated fields to include.
            sort: Field and order (e.g. '+level' or '-id').
            search: Text search in description and groups.

        Returns:
            data.affected_items: Rules with id, level, description, groups, mitre, filename.
        """
        params = {k: v for k, v in {
            "rule_ids": rule_ids, "status": status, "group": group, "level": level,
            "filename": filename, "relative_dirname": relative_dirname,
            "pci_dss": pci_dss, "gdpr": gdpr, "gpg13": gpg13,
            "hipaa": hipaa, "nist_800_53": nist_800_53, "tsc": tsc,
            "mitre": mitre, "limit": limit, "offset": offset,
            "select": select, "sort": sort, "search": search,
        }.items() if v is not None}
        return await client.get("/rules", params=params or None)

    @mcp.tool()
    async def list_rule_groups(
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
    ) -> dict:
        """
        Lists available rule groups.

        Args:
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Search by group name.

        Returns:
            data.affected_items: Names of available rule groups.
        """
        params = {k: v for k, v in {
            "limit": limit, "offset": offset, "sort": sort, "search": search,
        }.items() if v is not None}
        return await client.get("/rules/groups", params=params or None)

    @mcp.tool()
    async def list_rule_requirements(requirement: str) -> dict:
        """
        Lists unique values of a compliance requirement across active rules.

        Args:
            requirement: Standard to query. Values: 'pci_dss', 'gdpr', 'hipaa',
                         'nist_800_53', 'gpg13', 'tsc', 'mitre'.

        Returns:
            data.affected_items: Unique values of the requirement in active rules.
        """
        return await client.get(f"/rules/requirement/{requirement}")

    @mcp.tool()
    async def list_rules_files(
        status: Optional[str] = None,
        relative_dirname: Optional[str] = None,
        filename: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> dict:
        """
        Lists XML rule files with their path and status.

        Args:
            status: Filter by status. Values: 'enabled', 'disabled'.
            relative_dirname: Relative directory of the files.
            filename: File name to search for.
            limit: Maximum number of results.
            offset: Offset for pagination.

        Returns:
            data.affected_items: Rule files with filename, relative_dirname, status.
        """
        params = {k: v for k, v in {
            "status": status, "relative_dirname": relative_dirname,
            "filename": filename, "limit": limit, "offset": offset,
        }.items() if v is not None}
        return await client.get("/rules/files", params=params or None)

    @mcp.tool()
    async def get_rules_file(filename: str, raw: Optional[bool] = None) -> dict:
        """
        Returns the content of a rules file.

        Args:
            filename: XML rules file name (e.g. '0020-syslog_rules.xml').
            raw: If True, returns raw XML as a string; if False, returns parsed JSON.

        Returns:
            Rules file content in XML or JSON depending on the raw parameter.
        """
        params = {"raw": raw} if raw is not None else None
        return await client.get(f"/rules/files/{filename}", params=params)

    @mcp.tool()
    async def update_rules_file(
        filename: str,
        content: str,
        overwrite: Optional[bool] = None,
    ) -> dict:
        """
        Updates or creates a rules file on the manager.

        CAUTION: Overwrites the rules file. Back up before modifying.
        An analysisd reload or manager restart is required to apply changes.

        Args:
            filename: XML rules file name (e.g. 'local_rules.xml').
            content: Full XML content with the new rules.
            overwrite: If True, allows modifying existing files (required to edit).

        Returns:
            data.affected_items: Confirmation of the file update.
        """
        params = {"overwrite": overwrite} if overwrite is not None else None
        return await client.put(
            f"/rules/files/{filename}",
            content=content,
            content_type="application/octet-stream",
            params=params,
        )

    @mcp.tool()
    async def delete_rules_file(filename: str) -> dict:
        """
        Deletes a rules file from the manager.

        DESTRUCTIVE: Rules in the file will stop being applied after the next reload.

        Args:
            filename: XML file name to delete (e.g. 'local_rules.xml').

        Returns:
            data.affected_items: Confirmation of the deletion.
        """
        return await client.delete(f"/rules/files/{filename}")
