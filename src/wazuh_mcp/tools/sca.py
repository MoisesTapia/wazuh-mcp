from __future__ import annotations

from typing import Optional

from fastmcp import FastMCP

from ..client import WazuhClient


def register(mcp: FastMCP, client: WazuhClient) -> None:

    @mcp.tool()
    async def get_sca_results(
        agent_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        references: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Lists CIS policies evaluated on an agent via Security Configuration Assessment.

        Args:
            agent_id: Agent ID with zero-padding (e.g. '001').
            name: Filter by policy name.
            description: Filter by description.
            references: Filter by external references.
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order (e.g. '+score').
            search: Free text search.
            select: Comma-separated fields to include.
            q: Advanced query filter.

        Returns:
            data.affected_items: Policies with id, name, description, score,
                pass, fail, invalid, total_checks, hash_file.
        """
        params = {k: v for k, v in {
            "name": name, "description": description, "references": references,
            "limit": limit, "offset": offset, "sort": sort,
            "search": search, "select": select, "q": q,
        }.items() if v is not None}
        return await client.get(f"/sca/{agent_id}", params=params or None)

    @mcp.tool()
    async def get_sca_policy_checks(
        agent_id: str,
        policy_id: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        rationale: Optional[str] = None,
        remediation: Optional[str] = None,
        file: Optional[str] = None,
        process: Optional[str] = None,
        directory: Optional[str] = None,
        registry: Optional[str] = None,
        references: Optional[str] = None,
        result: Optional[str] = None,
        condition: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Lists individual checks for an SCA policy on an agent.

        Args:
            agent_id: Agent ID (e.g. '001').
            policy_id: SCA policy ID (e.g. 'cis_ubuntu20-04').
            title: Filter by check title.
            description: Filter by check description.
            rationale: Filter by rationale.
            remediation: Filter by remediation steps.
            file: Filter by evaluated file.
            process: Filter by evaluated process.
            directory: Filter by evaluated directory.
            registry: Filter by registry key (Windows).
            references: Filter by external references.
            result: Check status. Values: 'passed', 'failed', 'not applicable'.
            condition: Check condition (e.g. 'all', 'any', 'none').
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Free text search.
            select: Comma-separated fields to include.
            q: Advanced query filter.

        Returns:
            data.affected_items: Checks with id, title, result, rationale,
                remediation, compliance, rules.
        """
        params = {k: v for k, v in {
            "title": title, "description": description, "rationale": rationale,
            "remediation": remediation, "file": file, "process": process,
            "directory": directory, "registry": registry, "references": references,
            "result": result, "condition": condition,
            "limit": limit, "offset": offset, "sort": sort,
            "search": search, "select": select, "q": q,
        }.items() if v is not None}
        return await client.get(
            f"/sca/{agent_id}/checks/{policy_id}", params=params or None
        )
