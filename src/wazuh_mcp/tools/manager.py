from __future__ import annotations

from typing import Optional

from fastmcp import FastMCP

from ..client import WazuhClient
from ..sanitize import sanitize_output, wrap_external_content


def register(mcp: FastMCP, client: WazuhClient) -> None:

    @mcp.tool()
    async def get_manager_status() -> dict:
        """
        Returns the status of all manager daemons.

        Returns:
            data.affected_items: Status of each daemon (wazuh-analysisd, wazuh-remoted, etc.).
        """
        return await client.get("/manager/status")

    @mcp.tool()
    async def get_manager_info() -> dict:
        """
        Returns manager information: version, build, installation type, cluster mode.

        Returns:
            data.affected_items: Version, build date, type and mode of the manager.
        """
        return await client.get("/manager/info")

    @mcp.tool()
    @sanitize_output()
    async def get_manager_configuration(
        section: Optional[str] = None,
        field: Optional[str] = None,
    ) -> dict:
        """
        Returns the current manager configuration from ossec.conf.

        Args:
            section: Configuration section. Values: 'global', 'alerts', 'logging',
                     'remote', 'rootcheck', 'syscheck', 'vulnerability-detection', etc.
            field: Specific field within the section.

        Returns:
            data.affected_items: Manager configuration (ossec.conf contents).
        """
        params = {k: v for k, v in {"section": section, "field": field}.items() if v is not None}
        result = await client.get("/manager/configuration", params=params or None)
        return wrap_external_content(result, source="wazuh_api/manager/configuration")

    @mcp.tool()
    async def update_manager_configuration(xml_content: str) -> dict:
        """
        Replaces the manager's ossec.conf with new XML content.

        CAUTION: Overwrites ossec.conf. Requires a manager restart to take effect.
        Back up the current configuration before modifying.

        Args:
            xml_content: Full XML of the new configuration (ossec.conf contents).

        Returns:
            data.affected_items: Confirmation of the update.
        """
        return await client.put(
            "/manager/configuration",
            content=xml_content,
            content_type="application/octet-stream",
        )

    @mcp.tool()
    @sanitize_output()
    async def get_manager_active_configuration(
        component: str,
        configuration: str,
    ) -> dict:
        """
        Returns the manager's in-memory active configuration (no restart required).

        Args:
            component: Component to query (e.g. 'com', 'agent', 'syscheck').
            configuration: Configuration section (e.g. 'internal', 'labels').

        Returns:
            data.affected_items: Active in-memory configuration of the component.
        """
        return await client.get(f"/manager/configuration/{component}/{configuration}")

    @mcp.tool()
    async def validate_manager_configuration() -> dict:
        """
        Validates the current manager configuration without applying it.

        Returns:
            data.affected_items: Validation result with errors if any.
        """
        return await client.get("/manager/configuration/validation")

    @mcp.tool()
    async def get_manager_stats() -> dict:
        """
        Returns general manager statistics.

        Returns:
            data.affected_items: Event processing statistics of the manager.
        """
        return await client.get("/manager/stats")

    @mcp.tool()
    async def get_manager_stats_hourly() -> dict:
        """
        Returns manager statistics grouped by hour of day (0-23).

        Returns:
            data.affected_items: Statistics grouped by hour.
        """
        return await client.get("/manager/stats/hourly")

    @mcp.tool()
    async def get_manager_stats_weekly() -> dict:
        """
        Returns manager statistics grouped by day of the week.

        Returns:
            data.affected_items: Statistics grouped by day of the week.
        """
        return await client.get("/manager/stats/weekly")

    @mcp.tool()
    async def get_manager_stats_analysisd() -> dict:
        """
        Returns analysisd daemon statistics (events, alerts, decoded).

        Returns:
            data.affected_items: analysisd metrics: total_events_decoded, alerts_written, etc.
        """
        return await client.get("/manager/stats/analysisd")

    @mcp.tool()
    async def get_manager_stats_remoted() -> dict:
        """
        Returns remoted daemon statistics (agent communication).

        Returns:
            data.affected_items: remoted metrics: recv_ctrl, sent_bytes, etc.
        """
        return await client.get("/manager/stats/remoted")

    @mcp.tool()
    async def get_manager_daemon_stats(daemons_list: Optional[str] = None) -> dict:
        """
        Returns detailed statistics for specific manager daemons.

        Args:
            daemons_list: Comma-separated daemons. Values: 'wazuh-analysisd',
                          'wazuh-remoted', 'wazuh-db'.

        Returns:
            data.affected_items: Detailed statistics for each requested daemon.
        """
        params = {"daemons_list": daemons_list} if daemons_list is not None else None
        return await client.get("/manager/daemons/stats", params=params)

    @mcp.tool()
    @sanitize_output()
    async def get_manager_logs(
        level: Optional[str] = None,
        tag: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> dict:
        """
        Returns manager logs in real time.

        Args:
            level: Log level. Values: 'debug', 'info', 'warning', 'error', 'critical'.
            tag: Filter by tag/component (e.g. 'wazuh-analysisd').
            limit: Maximum number of entries to return.
            offset: Offset for pagination.

        Returns:
            data.affected_items: Log entries with timestamp, level, tag and message.
        """
        params = {k: v for k, v in {
            "level": level, "tag": tag, "limit": limit, "offset": offset,
        }.items() if v is not None}
        result = await client.get("/manager/logs", params=params or None)
        return wrap_external_content(result, source="wazuh_api/manager/logs")

    @mcp.tool()
    async def get_manager_logs_summary() -> dict:
        """
        Returns manager log counts grouped by category and level.

        Returns:
            data.affected_items: Log summary with count per category and level.
        """
        return await client.get("/manager/logs/summary")

    @mcp.tool()
    async def get_manager_api_config() -> dict:
        """
        Returns the current REST API configuration of the manager.

        Returns:
            data.affected_items: API configuration (host, port, SSL, logging, etc.).
        """
        return await client.get("/manager/api/config")

    @mcp.tool()
    async def reload_manager_analysisd() -> dict:
        """
        Reloads analysisd rules without restarting the service.

        CAUTION: There may be a brief interruption in event analysis during the reload.

        Returns:
            data.affected_items: Confirmation of the rule reload.
        """
        return await client.put("/manager/analysisd/reload")

    @mcp.tool()
    async def check_manager_updates() -> dict:
        """
        Checks whether Wazuh updates are available.

        Returns:
            data.affected_items: Information about available versions and changelog.
        """
        return await client.get("/manager/version/check")

    @mcp.tool()
    async def restart_manager() -> dict:
        """
        Restarts the full Wazuh manager.

        CAUTION: All agents will stop reporting until the manager is available again
        (~30 seconds). Do not use in production without a maintenance window.

        Returns:
            data.affected_items: Confirmation that the restart has been initiated.
        """
        return await client.put("/manager/restart")
