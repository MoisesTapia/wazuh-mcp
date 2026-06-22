from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

from ..client import WazuhClient
from ..sanitize import wrap_external_content


def register(mcp: FastMCP, client: WazuhClient) -> None:

    @mcp.tool()
    async def ingest_events(events: list[dict[str, Any]]) -> dict:
        """
        Ingests events directly into the Wazuh Manager without going through an agent.

        Useful for integrating external log sources or for rule testing.
        Events are processed by the rules analysis engine like any other log.

        Args:
            events: List of dicts in Wazuh event format.
                Each event must include at least: {'log': 'message text'}.
                Example: [{'log': 'Dec 25 10:00:00 host sshd: Accepted password for user'}].

        Returns:
            data with: affected_items (count of processed events),
                failed_items (events that failed with their error).
        """
        result = await client.post("/events", json={"events": events})
        return wrap_external_content(result, source="wazuh_api/events")
