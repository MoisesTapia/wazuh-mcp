from __future__ import annotations

from typing import Optional

from fastmcp import FastMCP

from ..client import WazuhClient


def register(mcp: FastMCP, client: WazuhClient) -> None:

    @mcp.tool()
    async def get_ciscat_results(
        agent_id: str,
        benchmark: Optional[str] = None,
        profile: Optional[str] = None,
        pass_: Optional[int] = None,
        fail: Optional[int] = None,
        error: Optional[int] = None,
        notchecked: Optional[int] = None,
        unknown: Optional[int] = None,
        score: Optional[int] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Returns CIS-CAT scan results for an agent.

        Note: Requires the CIS-CAT module to be configured and licensed in Wazuh.

        Args:
            agent_id: Agent ID with zero-padding (e.g. '001').
            benchmark: Filter by benchmark name (e.g. 'CIS Ubuntu Linux 20.04 LTS').
            profile: Filter by evaluation profile (e.g. 'Level 1 - Server').
            pass_: Filter by number of passed checks.
            fail: Filter by number of failed checks.
            error: Filter by number of checks with error.
            notchecked: Filter by number of unchecked items.
            unknown: Filter by number of checks with unknown result.
            score: Filter by minimum score (0-100).
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Free text search.
            select: Comma-separated fields to include.
            q: Advanced query filter.

        Returns:
            data.affected_items: Results with benchmark, profile, score,
                pass, fail, error, notchecked, unknown, datetime.
        """
        params = {k: v for k, v in {
            "benchmark": benchmark, "profile": profile,
            "pass": pass_, "fail": fail, "error": error,
            "notchecked": notchecked, "unknown": unknown, "score": score,
            "limit": limit, "offset": offset, "sort": sort,
            "search": search, "select": select, "q": q,
        }.items() if v is not None}
        return await client.get(
            f"/ciscat/{agent_id}/results", params=params or None
        )
