from __future__ import annotations

from typing import Optional

from fastmcp import FastMCP

from ..client import WazuhClient


def register(mcp: FastMCP, client: WazuhClient) -> None:

    @mcp.tool()
    async def list_agents(
        status: Optional[str] = None,
        group: Optional[str] = None,
        node_id: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> dict:
        """
        Lists registered Wazuh agents with optional filters.

        Args:
            status: Filter by status. Values: 'active', 'disconnected', 'pending', 'never_connected'.
            group: Filter by group name.
            node_id: Filter by cluster node.
            limit: Maximum number of results to return.
            offset: Offset for pagination.

        Returns:
            data.affected_items: List of agents with id, name, ip, status, os, version.
        """
        params = {k: v for k, v in {
            "status": status, "group": group,
            "node_id": node_id, "limit": limit, "offset": offset,
        }.items() if v is not None}
        return await client.get("/agents", params=params or None)

    @mcp.tool()
    async def get_agent(agent_id: str) -> dict:
        """
        Returns detailed information about an agent by its ID.

        Args:
            agent_id: Agent ID with zero-padding (e.g. '001', '042').

        Returns:
            data.affected_items: List containing the agent (id, name, ip, status, os, version).
        """
        return await client.get("/agents", params={"agents_list": agent_id})

    @mcp.tool()
    async def get_agent_config(
        agent_id: str,
        component: str,
        configuration: str,
    ) -> dict:
        """
        Returns the active configuration of a specific agent component.

        Args:
            agent_id: Agent ID (e.g. '001').
            component: Component to query (e.g. 'com', 'agent', 'syscheck').
            configuration: Configuration section (e.g. 'internal', 'labels').

        Returns:
            data.affected_items: Active configuration of the component.
        """
        return await client.get(f"/agents/{agent_id}/config/{component}/{configuration}")

    @mcp.tool()
    async def get_agent_key(agent_id: str) -> dict:
        """
        Returns the registration key of an agent.

        Args:
            agent_id: Agent ID (e.g. '001').

        Returns:
            data.affected_items: Registration key of the agent.
        """
        return await client.get(f"/agents/{agent_id}/key")

    @mcp.tool()
    async def get_agent_sync_status(agent_id: str) -> dict:
        """
        Checks whether the agent's group configuration is synchronized.

        Args:
            agent_id: Agent ID (e.g. '001').

        Returns:
            data.affected_items: Synchronization status (synced: true/false).
        """
        return await client.get(f"/agents/{agent_id}/group/is_sync")

    @mcp.tool()
    async def get_agents_summary() -> dict:
        """
        Returns summary information for all agents.

        Returns:
            data.affected_items: Summary with counts and agent statistics.
        """
        return await client.get("/agents/summary")

    @mcp.tool()
    async def get_agents_summary_os() -> dict:
        """
        Returns the distribution of operating systems across agents.

        Returns:
            data.affected_items: OS distribution among registered agents.
        """
        return await client.get("/agents/summary/os")

    @mcp.tool()
    async def get_agents_summary_status() -> dict:
        """
        Returns agent count by status.

        Returns:
            data.affected_items: Count by status (active, disconnected, pending, never_connected).
        """
        return await client.get("/agents/summary/status")

    @mcp.tool()
    async def list_agents_no_group() -> dict:
        """
        Lists agents with no group assigned.

        Returns:
            data.affected_items: List of agents without a group.
        """
        return await client.get("/agents/no_group")

    @mcp.tool()
    async def list_agents_outdated() -> dict:
        """
        Lists agents running an outdated version of Wazuh.

        Returns:
            data.affected_items: List of agents running a version older than the manager.
        """
        return await client.get("/agents/outdated")

    @mcp.tool()
    async def get_agents_upgrade_result(
        agents_list: Optional[str] = None,
        wait_for_complete: Optional[bool] = None,
    ) -> dict:
        """
        Returns the result of ongoing agent upgrades.

        Args:
            agents_list: Comma-separated agent IDs (e.g. '001,002').
            wait_for_complete: If True, waits until all upgrades finish.

        Returns:
            data.affected_items: Upgrade result with status and errors.
        """
        params = {k: v for k, v in {
            "agents_list": agents_list,
            "wait_for_complete": wait_for_complete,
        }.items() if v is not None}
        return await client.get("/agents/upgrade_result", params=params or None)

    @mcp.tool()
    async def get_agent_daemon_stats(agent_id: str) -> dict:
        """
        Returns daemon statistics for an agent.

        Args:
            agent_id: Agent ID (e.g. '001').

        Returns:
            data.affected_items: Statistics for each daemon on the agent.
        """
        return await client.get(f"/agents/{agent_id}/daemons/stats")

    @mcp.tool()
    async def get_agent_component_stats(agent_id: str, component: str) -> dict:
        """
        Returns statistics for a specific agent component.

        Args:
            agent_id: Agent ID (e.g. '001').
            component: Values: 'logcollector', 'agent'.

        Returns:
            data.affected_items: Statistics for the specified component.
        """
        return await client.get(f"/agents/{agent_id}/stats/{component}")

    @mcp.tool()
    async def get_agents_distinct_fields(
        fields: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> dict:
        """
        Returns unique values for agent fields.

        Args:
            fields: Comma-separated fields (e.g. 'os.platform,version').
            limit: Maximum number of results.
            offset: Offset for pagination.

        Returns:
            data.affected_items: Unique values for the requested fields.
        """
        params = {k: v for k, v in {
            "fields": fields, "limit": limit, "offset": offset,
        }.items() if v is not None}
        return await client.get("/agents/stats/distinct", params=params or None)

    @mcp.tool()
    async def add_agent(
        name: str,
        ip: Optional[str] = None,
        force: Optional[bool] = None,
    ) -> dict:
        """
        Creates a new Wazuh agent.

        Args:
            name: Unique agent name.
            ip: Agent IP address. If omitted, Wazuh detects it automatically.
            force: If True, allows replacing an existing agent with the same name/IP.

        Returns:
            data.affected_items: ID and registration key of the created agent.
        """
        body: dict = {"name": name}
        if ip is not None:
            body["ip"] = ip
        if force is not None:
            body["force"] = {"enabled": force}
        return await client.post("/agents", json=body)

    @mcp.tool()
    async def add_agent_quick(name: str) -> dict:
        """
        Creates an agent with only a name, without specifying IP or ID.

        Args:
            name: Unique agent name.

        Returns:
            data.affected_items: ID and registration key of the created agent.
        """
        return await client.post("/agents/insert/quick", json={"name": name})

    @mcp.tool()
    async def insert_agent_full(
        name: str,
        ip: Optional[str] = None,
        id: Optional[str] = None,
        key: Optional[str] = None,
        force: Optional[bool] = None,
    ) -> dict:
        """
        Inserts an agent with custom ID and key.

        Args:
            name: Agent name.
            ip: Agent IP address.
            id: Custom ID (e.g. '001').
            key: Custom registration key (base64, 32+ chars).
            force: If True, allows overwriting an existing agent.

        Returns:
            data.affected_items: Data of the inserted agent.
        """
        body: dict = {"name": name}
        if ip is not None:
            body["ip"] = ip
        if id is not None:
            body["id"] = id
        if key is not None:
            body["key"] = key
        if force is not None:
            body["force"] = {"enabled": force}
        return await client.post("/agents/insert", json=body)

    @mcp.tool()
    async def restart_agent(agent_id: str) -> dict:
        """
        Restarts the Wazuh service on a single agent.

        CAUTION: The agent will temporarily stop reporting during the restart.

        Args:
            agent_id: Agent ID (e.g. '001').

        Returns:
            data.affected_items: Confirmation of the agent restart.
        """
        return await client.put(f"/agents/{agent_id}/restart")

    @mcp.tool()
    async def restart_agents(
        agents_list: Optional[str] = None,
        group_id: Optional[str] = None,
        node_id: Optional[str] = None,
    ) -> dict:
        """
        Restarts multiple agents simultaneously.

        CAUTION: Restarts multiple agents at once. May reduce security visibility.

        Args:
            agents_list: Comma-separated agent IDs (e.g. '001,002').
            group_id: Restart all agents in this group.
            node_id: Restart all agents on this cluster node.

        Returns:
            data.affected_items: List of successfully restarted agents.
        """
        params = {k: v for k, v in {
            "agents_list": agents_list, "group_id": group_id, "node_id": node_id,
        }.items() if v is not None}
        return await client.put("/agents/restart", params=params or None)

    @mcp.tool()
    async def restart_agents_by_group(group_id: str) -> dict:
        """
        Restarts all agents belonging to a group.

        CAUTION: Restarts all agents in the group.

        Args:
            group_id: Name of the group whose agents will be restarted.

        Returns:
            data.affected_items: List of restarted agents.
        """
        return await client.put(f"/agents/group/{group_id}/restart")

    @mcp.tool()
    async def restart_agents_by_node(node_id: str) -> dict:
        """
        Restarts all agents connected to a cluster node.

        CAUTION: Restarts all agents on the node. May affect multiple sites.

        Args:
            node_id: Cluster node name.

        Returns:
            data.affected_items: List of restarted agents.
        """
        return await client.put(f"/agents/node/{node_id}/restart")

    @mcp.tool()
    async def reconnect_agents(
        agents_list: Optional[str] = None,
        group_id: Optional[str] = None,
        node_id: Optional[str] = None,
    ) -> dict:
        """
        Forces reconnection of disconnected agents.

        Args:
            agents_list: Comma-separated agent IDs to reconnect.
            group_id: Reconnect all agents in this group.
            node_id: Reconnect all agents on this node.

        Returns:
            data.affected_items: List of agents with reconnection initiated.
        """
        params = {k: v for k, v in {
            "agents_list": agents_list, "group_id": group_id, "node_id": node_id,
        }.items() if v is not None}
        return await client.put("/agents/reconnect", params=params or None)

    @mcp.tool()
    async def assign_agent_to_group(agent_id: str, group_id: str) -> dict:
        """
        Assigns a single agent to a group.

        Args:
            agent_id: Agent ID (e.g. '001').
            group_id: Target group name.

        Returns:
            data.affected_items: Confirmation of the assignment.
        """
        return await client.put(f"/agents/{agent_id}/group/{group_id}")

    @mcp.tool()
    async def assign_agents_to_group(agents_list: str, group_id: str) -> dict:
        """
        Assigns multiple agents to a group.

        Args:
            agents_list: Comma-separated agent IDs (e.g. '001,002,003').
            group_id: Target group name.

        Returns:
            data.affected_items: List of successfully assigned agents.
        """
        return await client.put(
            "/agents/group",
            params={"group_id": group_id, "agents_list": agents_list},
        )

    @mcp.tool()
    async def remove_agent_from_group(agent_id: str, group_id: str) -> dict:
        """
        Removes an agent from a specific group.

        Args:
            agent_id: Agent ID (e.g. '001').
            group_id: Name of the group to remove the agent from.

        Returns:
            data.affected_items: Confirmation of removal from the group.
        """
        return await client.delete(f"/agents/{agent_id}/group/{group_id}")

    @mcp.tool()
    async def remove_agent_from_all_groups(agent_id: str) -> dict:
        """
        Removes an agent from all its assigned groups.

        Args:
            agent_id: Agent ID (e.g. '001').

        Returns:
            data.affected_items: Confirmation; the agent will have no group.
        """
        return await client.delete(f"/agents/{agent_id}/group")

    @mcp.tool()
    async def remove_agents_from_group(agents_list: str, group_id: str) -> dict:
        """
        Removes multiple agents from a group.

        Args:
            agents_list: Comma-separated agent IDs (e.g. '001,002').
            group_id: Name of the group to remove agents from.

        Returns:
            data.affected_items: List of agents removed from the group.
        """
        return await client.delete(
            "/agents/group",
            params={"group_id": group_id, "agents_list": agents_list},
        )

    @mcp.tool()
    async def delete_agents(
        agents_list: str,
        status: str,
        purge: Optional[bool] = None,
    ) -> dict:
        """
        Permanently deletes agents from Wazuh.

        DESTRUCTIVE: This operation cannot be undone.

        Args:
            agents_list: Comma-separated IDs or 'all'.
            status: Required. Values: 'all', 'active', 'disconnected', 'pending', 'never_connected'.
            purge: If True, also deletes the agent data directory.

        Returns:
            data.affected_items: List of deleted agents.
            data.failed_items: Agents that could not be deleted.
        """
        params: dict = {"agents_list": agents_list, "status": status}
        if purge is not None:
            params["purge"] = purge
        return await client.delete("/agents", params=params)

    @mcp.tool()
    async def upgrade_agents(
        agents_list: str,
        wpk_repo: Optional[str] = None,
        version: Optional[str] = None,
        force: Optional[bool] = None,
        use_http: Optional[bool] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Upgrades the Wazuh version on the selected agents.

        CAUTION: Agents will restart during the upgrade.

        Args:
            agents_list: Comma-separated agent IDs.
            wpk_repo: URL of a custom WPK repository.
            version: Wazuh version to install (e.g. 'v4.7.0').
            force: If True, forces the upgrade even if the version is the same.
            use_http: If True, uses HTTP instead of HTTPS to download the WPK.
            q: Additional query filter.

        Returns:
            data.affected_items: Agents with upgrade initiated.
        """
        params = {k: v for k, v in {
            "agents_list": agents_list, "wpk_repo": wpk_repo,
            "version": version, "force": force, "use_http": use_http, "q": q,
        }.items() if v is not None}
        return await client.put("/agents/upgrade", params=params)

    @mcp.tool()
    async def upgrade_agents_custom(
        agents_list: str,
        file_path: str,
        installer: Optional[str] = None,
    ) -> dict:
        """
        Upgrades agents with a custom WPK package hosted on the manager.

        CAUTION: Agents will restart during the upgrade.

        Args:
            agents_list: Comma-separated agent IDs.
            file_path: Path to the WPK file on the manager.
            installer: Installer script inside the WPK (e.g. 'upgrade.sh').

        Returns:
            data.affected_items: Agents with custom upgrade initiated.
        """
        params = {k: v for k, v in {
            "agents_list": agents_list, "file_path": file_path, "installer": installer,
        }.items() if v is not None}
        return await client.put("/agents/upgrade_custom", params=params)
