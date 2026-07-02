from __future__ import annotations

from typing import Optional

from fastmcp import FastMCP

from ..client import WazuhClient
from ..sanitize import sanitize_output


def register(mcp: FastMCP, client: WazuhClient) -> None:

    @mcp.tool()
    async def get_cluster_status() -> dict:
        """
        Returns the cluster status: whether it is enabled and whether the node is master or worker.

        Returns:
            data.affected_items: enabled ('yes'/'no') and running ('yes'/'no').
        """
        return await client.get("/cluster/status")

    @mcp.tool()
    async def get_cluster_local_node_info() -> dict:
        """
        Returns information about the local cluster node.

        Returns:
            data.affected_items: Name, type (master/worker) and version of the local node.
        """
        return await client.get("/cluster/local/info")

    @mcp.tool()
    async def get_cluster_local_config() -> dict:
        """
        Returns the cluster configuration of the local node.

        Returns:
            data.affected_items: Cluster configuration: name, node_name, node_type, key, port, etc.
        """
        return await client.get("/cluster/local/config")

    @mcp.tool()
    async def get_cluster_nodes(
        nodes_list: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        type: Optional[str] = None,
    ) -> dict:
        """
        Lists all cluster nodes with name, IP, version, type and status.

        Args:
            nodes_list: Comma-separated node names.
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order (e.g. '+name').
            search: Search by node name.
            select: Comma-separated fields to include.
            type: Filter by node type. Values: 'master', 'worker'.

        Returns:
            data.affected_items: Nodes with name, ip, version, type, status.
        """
        params = {k: v for k, v in {
            "nodes_list": nodes_list, "limit": limit, "offset": offset,
            "sort": sort, "search": search, "select": select, "type": type,
        }.items() if v is not None}
        return await client.get("/cluster/nodes", params=params or None)

    @mcp.tool()
    async def get_cluster_healthcheck(nodes_list: Optional[str] = None) -> dict:
        """
        Returns the health status of each cluster node.

        Args:
            nodes_list: Comma-separated node names to query.
                        If omitted, queries all nodes.

        Returns:
            data.affected_items: Status of each node: last sync, pending files.
        """
        params = {"nodes_list": nodes_list} if nodes_list is not None else None
        return await client.get("/cluster/healthcheck", params=params)

    @mcp.tool()
    async def get_cluster_ruleset_sync_status() -> dict:
        """
        Checks whether the ruleset is synchronized across all cluster nodes.

        Returns:
            data.affected_items: Ruleset synchronization status per node.
        """
        return await client.get("/cluster/ruleset/synchronization")

    @mcp.tool()
    async def get_cluster_api_config() -> dict:
        """
        Returns the REST API configuration across all cluster nodes.

        Returns:
            data.affected_items: API configuration per node.
        """
        return await client.get("/cluster/api/config")

    @mcp.tool()
    async def get_cluster_node_status(node_id: str) -> dict:
        """
        Returns the daemon status on a specific cluster node.

        Args:
            node_id: Cluster node name.

        Returns:
            data.affected_items: Status of each daemon on the specified node.
        """
        return await client.get(f"/cluster/{node_id}/status")

    @mcp.tool()
    async def get_cluster_node_info(node_id: str) -> dict:
        """
        Returns information about a specific cluster node.

        Args:
            node_id: Cluster node name.

        Returns:
            data.affected_items: Version, name and type of the specified node.
        """
        return await client.get(f"/cluster/{node_id}/info")

    @mcp.tool()
    async def get_cluster_node_config(
        node_id: str,
        section: Optional[str] = None,
        field: Optional[str] = None,
    ) -> dict:
        """
        Returns the ossec.conf configuration of a specific cluster node.

        Args:
            node_id: Cluster node name.
            section: Configuration section (e.g. 'global', 'alerts', 'remote').
            field: Specific field within the section.

        Returns:
            data.affected_items: Configuration of the specified node.
        """
        params = {k: v for k, v in {"section": section, "field": field}.items() if v is not None}
        return await client.get(f"/cluster/{node_id}/configuration", params=params or None)

    @mcp.tool()
    async def update_cluster_node_config(node_id: str, xml_content: str) -> dict:
        """
        Replaces the ossec.conf of a remote cluster node with new XML content.

        CAUTION: Modifies the remote node configuration. Requires a node restart to take effect.

        Args:
            node_id: Cluster node name.
            xml_content: Full XML of the new configuration.

        Returns:
            data.affected_items: Confirmation of the update.
        """
        return await client.put(
            f"/cluster/{node_id}/configuration",
            content=xml_content,
            content_type="application/octet-stream",
        )

    @mcp.tool()
    async def validate_cluster_config() -> dict:
        """
        Validates configuration on all cluster nodes without applying it.

        Returns:
            data.affected_items: Validation result per node with errors if any.
        """
        return await client.get("/cluster/configuration/validation")

    @mcp.tool()
    async def get_cluster_node_active_config(
        node_id: str,
        component: str,
        configuration: str,
    ) -> dict:
        """
        Returns the active in-memory configuration of a component on a cluster node.

        Args:
            node_id: Cluster node name.
            component: Component to query (e.g. 'com', 'agent', 'syscheck').
            configuration: Configuration section (e.g. 'internal', 'labels').

        Returns:
            data.affected_items: Active configuration of the component on the node.
        """
        return await client.get(f"/cluster/{node_id}/configuration/{component}/{configuration}")

    @mcp.tool()
    async def get_cluster_node_daemon_stats(
        node_id: str,
        daemons_list: Optional[str] = None,
    ) -> dict:
        """
        Returns daemon statistics for a specific cluster node.

        Args:
            node_id: Cluster node name.
            daemons_list: Comma-separated daemons: 'wazuh-analysisd', 'wazuh-remoted', 'wazuh-db'.

        Returns:
            data.affected_items: Detailed statistics of the node's daemons.
        """
        params = {"daemons_list": daemons_list} if daemons_list is not None else None
        return await client.get(f"/cluster/{node_id}/daemons/stats", params=params)

    @mcp.tool()
    async def get_cluster_node_stats(node_id: str, date: Optional[str] = None) -> dict:
        """
        Returns general statistics for a cluster node.

        Args:
            node_id: Cluster node name.
            date: Statistics date in YYYYMMDD format (e.g. '20240101').

        Returns:
            data.affected_items: Statistics of the specified node.
        """
        params = {"date": date} if date is not None else None
        return await client.get(f"/cluster/{node_id}/stats", params=params)

    @mcp.tool()
    async def get_cluster_node_stats_hourly(node_id: str) -> dict:
        """
        Returns hourly statistics for a cluster node.

        Args:
            node_id: Cluster node name.

        Returns:
            data.affected_items: Statistics grouped by hour (0-23).
        """
        return await client.get(f"/cluster/{node_id}/stats/hourly")

    @mcp.tool()
    async def get_cluster_node_stats_weekly(node_id: str) -> dict:
        """
        Returns weekly statistics for a cluster node.

        Args:
            node_id: Cluster node name.

        Returns:
            data.affected_items: Statistics grouped by day of the week.
        """
        return await client.get(f"/cluster/{node_id}/stats/weekly")

    @mcp.tool()
    async def get_cluster_node_stats_analysisd(node_id: str) -> dict:
        """
        Returns analysisd statistics for a cluster node.

        Args:
            node_id: Cluster node name.

        Returns:
            data.affected_items: analysisd metrics for the node.
        """
        return await client.get(f"/cluster/{node_id}/stats/analysisd")

    @mcp.tool()
    async def get_cluster_node_stats_remoted(node_id: str) -> dict:
        """
        Returns remoted statistics for a cluster node.

        Args:
            node_id: Cluster node name.

        Returns:
            data.affected_items: remoted metrics for the node.
        """
        return await client.get(f"/cluster/{node_id}/stats/remoted")

    @mcp.tool()
    @sanitize_output()
    async def get_cluster_node_logs(
        node_id: str,
        level: Optional[str] = None,
        tag: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> dict:
        """
        Returns logs from a specific cluster node.

        Args:
            node_id: Cluster node name.
            level: Log level. Values: 'debug', 'info', 'warning', 'error', 'critical'.
            tag: Filter by component (e.g. 'wazuh-analysisd').
            limit: Maximum number of entries.
            offset: Offset for pagination.

        Returns:
            data.affected_items: Log entries with timestamp, level, tag and message.
        """
        params = {k: v for k, v in {
            "level": level, "tag": tag, "limit": limit, "offset": offset,
        }.items() if v is not None}
        return await client.get(f"/cluster/{node_id}/logs", params=params or None)

    @mcp.tool()
    async def get_cluster_node_logs_summary(node_id: str) -> dict:
        """
        Returns a log summary for a cluster node grouped by category.

        Args:
            node_id: Cluster node name.

        Returns:
            data.affected_items: Log count by category and level on the node.
        """
        return await client.get(f"/cluster/{node_id}/logs/summary")

    @mcp.tool()
    async def restart_cluster(nodes_list: Optional[str] = None) -> dict:
        """
        Restarts one or all cluster nodes.

        CAUTION: Production impact. Restarted nodes will temporarily stop processing events.
        Confirm with the team before running in production.

        Args:
            nodes_list: Comma-separated node names to restart.
                        If omitted, restarts ALL cluster nodes.

        Returns:
            data.affected_items: List of nodes with restart initiated.
        """
        params = {"nodes_list": nodes_list} if nodes_list is not None else None
        return await client.put("/cluster/restart", params=params)

    @mcp.tool()
    async def reload_cluster_analysisd() -> dict:
        """
        Reloads analysisd rules on all cluster nodes without restarting them.

        CAUTION: There may be a brief interruption in event analysis across all cluster nodes
        during the reload.

        Returns:
            data.affected_items: Confirmation of the reload on each node.
        """
        return await client.put("/cluster/analysisd/reload")
