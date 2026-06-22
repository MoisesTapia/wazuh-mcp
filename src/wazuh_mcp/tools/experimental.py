from __future__ import annotations

from typing import Optional

from fastmcp import FastMCP

from ..client import WazuhClient


def register(mcp: FastMCP, client: WazuhClient) -> None:

    @mcp.tool()
    async def get_all_agents_hardware(
        agents_list: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Returns hardware for multiple agents in a single query (experimental).

        More efficient than iterating per agent for infrastructure audits.

        Args:
            agents_list: Comma-separated agent IDs. If omitted, returns all.
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Free text search.
            select: Comma-separated fields to include.
            q: Advanced query filter.

        Returns:
            data.affected_items: Hardware (cpu, ram, board_serial) per agent.
        """
        params = {k: v for k, v in {
            "agents_list": agents_list, "limit": limit, "offset": offset,
            "sort": sort, "search": search, "select": select, "q": q,
        }.items() if v is not None}
        return await client.get(
            "/experimental/syscollector/hardware", params=params or None
        )

    @mcp.tool()
    async def get_all_agents_os(
        agents_list: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Returns OS information for multiple agents in a single query (experimental).

        Args:
            agents_list: Comma-separated agent IDs. If omitted, returns all.
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Free text search.
            select: Comma-separated fields to include.
            q: Advanced query filter.

        Returns:
            data.affected_items: OS (name, version, platform, architecture) per agent.
        """
        params = {k: v for k, v in {
            "agents_list": agents_list, "limit": limit, "offset": offset,
            "sort": sort, "search": search, "select": select, "q": q,
        }.items() if v is not None}
        return await client.get(
            "/experimental/syscollector/os", params=params or None
        )

    @mcp.tool()
    async def get_all_agents_packages(
        agents_list: Optional[str] = None,
        package_name: Optional[str] = None,
        vendor: Optional[str] = None,
        version: Optional[str] = None,
        architecture: Optional[str] = None,
        format: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Returns installed packages for multiple agents in a single query (experimental).

        Args:
            agents_list: Comma-separated agent IDs.
            package_name: Filter by package name.
            vendor: Filter by vendor.
            version: Filter by version.
            architecture: Filter by architecture (e.g. 'amd64', 'x86_64').
            format: Filter by package format (e.g. 'deb', 'rpm').
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Free text search.
            select: Comma-separated fields to include.
            q: Advanced query filter.

        Returns:
            data.affected_items: Packages with name, version, vendor, architecture per agent.
        """
        params = {k: v for k, v in {
            "agents_list": agents_list, "name": package_name, "vendor": vendor,
            "version": version, "architecture": architecture, "format": format,
            "limit": limit, "offset": offset, "sort": sort,
            "search": search, "select": select, "q": q,
        }.items() if v is not None}
        return await client.get(
            "/experimental/syscollector/packages", params=params or None
        )

    @mcp.tool()
    async def get_all_agents_processes(
        agents_list: Optional[str] = None,
        pid: Optional[int] = None,
        state: Optional[str] = None,
        name: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Returns running processes for multiple agents in a single query (experimental).

        Args:
            agents_list: Comma-separated agent IDs.
            pid: Filter by process ID.
            state: Filter by process state (e.g. 'running', 'sleeping').
            name: Filter by process name.
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Free text search.
            select: Comma-separated fields to include.
            q: Advanced query filter.

        Returns:
            data.affected_items: Processes with pid, name, state, ppid, cmd per agent.
        """
        params = {k: v for k, v in {
            "agents_list": agents_list, "pid": pid, "state": state, "name": name,
            "limit": limit, "offset": offset, "sort": sort,
            "search": search, "select": select, "q": q,
        }.items() if v is not None}
        return await client.get(
            "/experimental/syscollector/processes", params=params or None
        )

    @mcp.tool()
    async def get_all_agents_ports(
        agents_list: Optional[str] = None,
        pid: Optional[int] = None,
        protocol: Optional[str] = None,
        local_port: Optional[int] = None,
        state: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Returns open ports for multiple agents in a single query (experimental).

        Args:
            agents_list: Comma-separated agent IDs.
            pid: Filter by PID of the process holding the port.
            protocol: Filter by protocol (e.g. 'tcp', 'udp').
            local_port: Filter by local port number.
            state: Filter by socket state (e.g. 'listening', 'established').
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Free text search.
            select: Comma-separated fields to include.
            q: Advanced query filter.

        Returns:
            data.affected_items: Ports with local_ip, local_port, protocol, state, pid per agent.
        """
        params = {k: v for k, v in {
            "agents_list": agents_list, "pid": pid, "protocol": protocol,
            "local_port": local_port, "state": state,
            "limit": limit, "offset": offset, "sort": sort,
            "search": search, "select": select, "q": q,
        }.items() if v is not None}
        return await client.get(
            "/experimental/syscollector/ports", params=params or None
        )

    @mcp.tool()
    async def get_all_agents_network_addresses(
        agents_list: Optional[str] = None,
        iface: Optional[str] = None,
        proto: Optional[str] = None,
        address: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Returns network addresses for multiple agents in a single query (experimental).

        Args:
            agents_list: Comma-separated agent IDs.
            iface: Filter by interface name (e.g. 'eth0').
            proto: Filter by protocol (e.g. 'ipv4', 'ipv6').
            address: Filter by IP address.
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Free text search.
            select: Comma-separated fields to include.
            q: Advanced query filter.

        Returns:
            data.affected_items: Addresses with iface, address, netmask, broadcast per agent.
        """
        params = {k: v for k, v in {
            "agents_list": agents_list, "iface": iface, "proto": proto, "address": address,
            "limit": limit, "offset": offset, "sort": sort,
            "search": search, "select": select, "q": q,
        }.items() if v is not None}
        return await client.get(
            "/experimental/syscollector/netaddr", params=params or None
        )

    @mcp.tool()
    async def get_all_agents_network_interfaces(
        agents_list: Optional[str] = None,
        name: Optional[str] = None,
        adapter: Optional[str] = None,
        type: Optional[str] = None,
        state: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Returns network interfaces for multiple agents in a single query (experimental).

        Args:
            agents_list: Comma-separated agent IDs.
            name: Filter by interface name.
            adapter: Filter by adapter.
            type: Filter by interface type (e.g. 'ethernet', 'loopback').
            state: Filter by state (e.g. 'up', 'down').
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Free text search.
            select: Comma-separated fields to include.
            q: Advanced query filter.

        Returns:
            data.affected_items: Interfaces with name, type, state, mac, mtu per agent.
        """
        params = {k: v for k, v in {
            "agents_list": agents_list, "name": name, "adapter": adapter,
            "type": type, "state": state,
            "limit": limit, "offset": offset, "sort": sort,
            "search": search, "select": select, "q": q,
        }.items() if v is not None}
        return await client.get(
            "/experimental/syscollector/netiface", params=params or None
        )

    @mcp.tool()
    async def get_all_agents_network_protocols(
        agents_list: Optional[str] = None,
        iface: Optional[str] = None,
        type: Optional[str] = None,
        gateway: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Returns network protocols for multiple agents in a single query (experimental).

        Args:
            agents_list: Comma-separated agent IDs.
            iface: Filter by interface name.
            type: Filter by protocol type (e.g. 'ipv4', 'ipv6').
            gateway: Filter by default gateway.
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Free text search.
            select: Comma-separated fields to include.
            q: Advanced query filter.

        Returns:
            data.affected_items: Protocols with iface, type, gateway, dhcp per agent.
        """
        params = {k: v for k, v in {
            "agents_list": agents_list, "iface": iface, "type": type, "gateway": gateway,
            "limit": limit, "offset": offset, "sort": sort,
            "search": search, "select": select, "q": q,
        }.items() if v is not None}
        return await client.get(
            "/experimental/syscollector/netproto", params=params or None
        )

    @mcp.tool()
    async def get_all_agents_hotfixes(
        agents_list: Optional[str] = None,
        hotfix: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Returns installed hotfixes (Windows) for multiple agents in a single query (experimental).

        Args:
            agents_list: Comma-separated agent IDs.
            hotfix: Filter by hotfix ID (e.g. 'KB4562830').
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Free text search.
            select: Comma-separated fields to include.
            q: Advanced query filter.

        Returns:
            data.affected_items: Hotfixes with hotfix, agent_id per Windows agent.
        """
        params = {k: v for k, v in {
            "agents_list": agents_list, "hotfix": hotfix,
            "limit": limit, "offset": offset, "sort": sort,
            "search": search, "select": select, "q": q,
        }.items() if v is not None}
        return await client.get(
            "/experimental/syscollector/hotfixes", params=params or None
        )

    @mcp.tool()
    async def get_all_agents_ciscat_results(
        agents_list: Optional[str] = None,
        benchmark: Optional[str] = None,
        profile: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """
        Returns CIS-CAT results for multiple agents in a single query (experimental).

        Args:
            agents_list: Comma-separated agent IDs.
            benchmark: Filter by benchmark name.
            profile: Filter by evaluation profile.
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Free text search.
            select: Comma-separated fields to include.
            q: Advanced query filter.

        Returns:
            data.affected_items: CIS-CAT results with benchmark, profile, score per agent.
        """
        params = {k: v for k, v in {
            "agents_list": agents_list, "benchmark": benchmark, "profile": profile,
            "limit": limit, "offset": offset, "sort": sort,
            "search": search, "select": select, "q": q,
        }.items() if v is not None}
        return await client.get(
            "/experimental/ciscat/results", params=params or None
        )

    @mcp.tool()
    async def clear_all_agents_rootcheck(
        agents_list: Optional[str] = None,
    ) -> dict:
        """
        Clears rootcheck results for multiple agents at once (experimental).

        DESTRUCTIVE: Deletes rootcheck results for all specified agents.
        This operation cannot be undone.

        Args:
            agents_list: Comma-separated agent IDs. If omitted, clears for all agents.

        Returns:
            data.affected_items: Agents where results were cleared.
        """
        params = {"agents_list": agents_list} if agents_list is not None else None
        return await client.delete("/experimental/rootcheck", params=params)

    @mcp.tool()
    async def clear_all_agents_syscheck(
        agents_list: Optional[str] = None,
    ) -> dict:
        """
        Clears FIM (syscheck) results for multiple agents at once (experimental).

        DESTRUCTIVE: Deletes File Integrity Monitoring results for the agents.
        This operation cannot be undone.

        Args:
            agents_list: Comma-separated agent IDs. If omitted, clears for all agents.

        Returns:
            data.affected_items: Agents where FIM results were cleared.
        """
        params = {"agents_list": agents_list} if agents_list is not None else None
        return await client.delete("/experimental/syscheck", params=params)
