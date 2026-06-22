from __future__ import annotations

from typing import Optional

from fastmcp import FastMCP

from ..client import WazuhClient


def register(mcp: FastMCP, client: WazuhClient) -> None:

    @mcp.tool()
    async def get_agent_hardware(
        agent_id: str,
        select: Optional[str] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
    ) -> dict:
        """
        Returns hardware information for an agent: CPU, RAM, architecture.

        Args:
            agent_id: Agent ID (e.g. '001').
            select: Comma-separated fields to include.
            sort: Field and order.
            search: Text search.

        Returns:
            data.affected_items: CPU (name, cores, MHz), RAM (total, free), board_serial.
        """
        params = {k: v for k, v in {
            "select": select, "sort": sort, "search": search,
        }.items() if v is not None}
        return await client.get(f"/syscollector/{agent_id}/hardware", params=params or None)

    @mcp.tool()
    async def get_agent_os(agent_id: str, select: Optional[str] = None) -> dict:
        """
        Returns operating system information for an agent.

        Args:
            agent_id: Agent ID (e.g. '001').
            select: Comma-separated fields to include.

        Returns:
            data.affected_items: OS name, version, release, kernel, hostname, architecture.
        """
        params = {"select": select} if select is not None else None
        return await client.get(f"/syscollector/{agent_id}/os", params=params)

    @mcp.tool()
    async def get_agent_packages(
        agent_id: str,
        name: Optional[str] = None,
        vendor: Optional[str] = None,
        version: Optional[str] = None,
        architecture: Optional[str] = None,
        format: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
    ) -> dict:
        """
        Lists installed packages on an agent.

        Args:
            agent_id: Agent ID (e.g. '001').
            name: Filter by package name.
            vendor: Filter by vendor.
            version: Filter by version.
            architecture: Filter by architecture (e.g. 'x86_64', 'amd64').
            format: Package format (e.g. 'deb', 'rpm', 'win').
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order (e.g. '+name').
            search: Text search in name and description.
            select: Comma-separated fields to include.

        Returns:
            data.affected_items: Packages with name, version, vendor, architecture, format.
        """
        params = {k: v for k, v in {
            "name": name, "vendor": vendor, "version": version,
            "architecture": architecture, "format": format,
            "limit": limit, "offset": offset,
            "sort": sort, "search": search, "select": select,
        }.items() if v is not None}
        return await client.get(f"/syscollector/{agent_id}/packages", params=params or None)

    @mcp.tool()
    async def get_agent_processes(
        agent_id: str,
        pid: Optional[int] = None,
        state: Optional[str] = None,
        ppid: Optional[int] = None,
        egroup: Optional[str] = None,
        euser: Optional[str] = None,
        fgroup: Optional[str] = None,
        name: Optional[str] = None,
        nlwp: Optional[int] = None,
        pgrp: Optional[int] = None,
        priority: Optional[int] = None,
        rgroup: Optional[str] = None,
        ruser: Optional[str] = None,
        sgroup: Optional[str] = None,
        suser: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
    ) -> dict:
        """
        Lists processes running on an agent.

        Args:
            agent_id: Agent ID (e.g. '001').
            pid: Filter by PID.
            state: Filter by process state (e.g. 'running', 'sleeping').
            ppid: Filter by parent PID.
            egroup: Filter by effective group.
            euser: Filter by effective user.
            fgroup: Filter by filesystem group.
            name: Filter by process name.
            nlwp: Number of threads in the process.
            pgrp: Process group ID.
            priority: Process priority.
            rgroup: Real group.
            ruser: Real user.
            sgroup: Saved group.
            suser: Saved user.
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order (e.g. '+pid').
            search: Text search in name and arguments.
            select: Comma-separated fields to include.

        Returns:
            data.affected_items: Processes with pid, name, state, ppid, euser, cpu, vm_size.
        """
        params = {k: v for k, v in {
            "pid": pid, "state": state, "ppid": ppid,
            "egroup": egroup, "euser": euser, "fgroup": fgroup,
            "name": name, "nlwp": nlwp, "pgrp": pgrp, "priority": priority,
            "rgroup": rgroup, "ruser": ruser, "sgroup": sgroup, "suser": suser,
            "limit": limit, "offset": offset,
            "sort": sort, "search": search, "select": select,
        }.items() if v is not None}
        return await client.get(f"/syscollector/{agent_id}/processes", params=params or None)

    @mcp.tool()
    async def get_agent_ports(
        agent_id: str,
        pid: Optional[int] = None,
        protocol: Optional[str] = None,
        local_ip: Optional[str] = None,
        local_port: Optional[int] = None,
        remote_ip: Optional[str] = None,
        state: Optional[str] = None,
        process: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
    ) -> dict:
        """
        Lists network ports in use on an agent.

        Args:
            agent_id: Agent ID (e.g. '001').
            pid: Filter by process PID.
            protocol: Filter by protocol. Values: 'tcp', 'udp'.
            local_ip: Filter by local listening IP.
            local_port: Filter by local port.
            remote_ip: Filter by remote IP.
            state: Port state (e.g. 'listening', 'established').
            process: Filter by process name.
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Text search.
            select: Comma-separated fields to include.

        Returns:
            data.affected_items: Ports with protocol, local_ip, local_port, remote_ip, state, process.
        """
        params = {k: v for k, v in {
            "pid": pid, "protocol": protocol, "local_ip": local_ip,
            "local_port": local_port, "remote_ip": remote_ip,
            "state": state, "process": process,
            "limit": limit, "offset": offset,
            "sort": sort, "search": search, "select": select,
        }.items() if v is not None}
        return await client.get(f"/syscollector/{agent_id}/ports", params=params or None)

    @mcp.tool()
    async def get_agent_network_addresses(
        agent_id: str,
        iface: Optional[str] = None,
        proto: Optional[str] = None,
        address: Optional[str] = None,
        broadcast: Optional[str] = None,
        netmask: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
    ) -> dict:
        """
        Lists IP addresses for each network interface on an agent.

        Args:
            agent_id: Agent ID (e.g. '001').
            iface: Filter by interface name (e.g. 'eth0').
            proto: Filter by protocol. Values: 'ipv4', 'ipv6'.
            address: Filter by IP address.
            broadcast: Filter by broadcast address.
            netmask: Filter by network mask.
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Text search.
            select: Comma-separated fields to include.

        Returns:
            data.affected_items: Addresses with iface, address, netmask, broadcast, proto.
        """
        params = {k: v for k, v in {
            "iface": iface, "proto": proto, "address": address,
            "broadcast": broadcast, "netmask": netmask,
            "limit": limit, "offset": offset,
            "sort": sort, "search": search, "select": select,
        }.items() if v is not None}
        return await client.get(f"/syscollector/{agent_id}/netaddr", params=params or None)

    @mcp.tool()
    async def get_agent_network_interfaces(
        agent_id: str,
        name: Optional[str] = None,
        adapter: Optional[str] = None,
        type: Optional[str] = None,
        state: Optional[str] = None,
        mtu: Optional[int] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
    ) -> dict:
        """
        Lists network interfaces on an agent with MTU, MAC, state and speed.

        Args:
            agent_id: Agent ID (e.g. '001').
            name: Filter by interface name (e.g. 'eth0').
            adapter: Filter by adapter.
            type: Filter by interface type (e.g. 'ethernet').
            state: Filter by state (e.g. 'up', 'down').
            mtu: Filter by MTU.
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Text search.
            select: Comma-separated fields to include.

        Returns:
            data.affected_items: Interfaces with name, mac, mtu, state, speed, type.
        """
        params = {k: v for k, v in {
            "name": name, "adapter": adapter, "type": type, "state": state, "mtu": mtu,
            "limit": limit, "offset": offset,
            "sort": sort, "search": search, "select": select,
        }.items() if v is not None}
        return await client.get(f"/syscollector/{agent_id}/netiface", params=params or None)

    @mcp.tool()
    async def get_agent_network_protocols(
        agent_id: str,
        iface: Optional[str] = None,
        type: Optional[str] = None,
        gateway: Optional[str] = None,
        dhcp: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
    ) -> dict:
        """
        Lists network protocols configured per interface on an agent.

        Args:
            agent_id: Agent ID (e.g. '001').
            iface: Filter by interface name.
            type: Filter by protocol type (e.g. 'ipv4', 'ipv6').
            gateway: Filter by gateway.
            dhcp: Filter by DHCP state (e.g. 'enabled', 'disabled').
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Text search.
            select: Comma-separated fields to include.

        Returns:
            data.affected_items: Protocols with iface, type, gateway, dhcp, dns_servers.
        """
        params = {k: v for k, v in {
            "iface": iface, "type": type, "gateway": gateway, "dhcp": dhcp,
            "limit": limit, "offset": offset,
            "sort": sort, "search": search, "select": select,
        }.items() if v is not None}
        return await client.get(f"/syscollector/{agent_id}/netproto", params=params or None)

    @mcp.tool()
    async def get_agent_hotfixes(
        agent_id: str,
        hotfix: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
    ) -> dict:
        """
        Lists Windows hotfixes installed on an agent.

        Args:
            agent_id: Agent ID (e.g. '001').
            hotfix: Filter by hotfix ID (e.g. 'KB4534310').
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Text search.
            select: Comma-separated fields to include.

        Returns:
            data.affected_items: Hotfixes with hotfix (e.g. 'KB4534310').
        """
        params = {k: v for k, v in {
            "hotfix": hotfix, "limit": limit, "offset": offset,
            "sort": sort, "search": search, "select": select,
        }.items() if v is not None}
        return await client.get(f"/syscollector/{agent_id}/hotfixes", params=params or None)

    @mcp.tool()
    async def get_agent_users(
        agent_id: str,
        user_name: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
    ) -> dict:
        """
        Lists operating system users on an agent.

        Args:
            agent_id: Agent ID (e.g. '001').
            user_name: Filter by username.
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Text search.
            select: Comma-separated fields to include.

        Returns:
            data.affected_items: Users with name, uid, gid, shell, home, last_login.
        """
        params = {k: v for k, v in {
            "user_name": user_name, "limit": limit, "offset": offset,
            "sort": sort, "search": search, "select": select,
        }.items() if v is not None}
        return await client.get(f"/syscollector/{agent_id}/users", params=params or None)

    @mcp.tool()
    async def get_agent_system_groups(
        agent_id: str,
        group_name: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> dict:
        """
        Lists operating system groups on an agent.

        Args:
            agent_id: Agent ID (e.g. '001').
            group_name: Filter by group name.
            limit: Maximum number of results.
            offset: Offset for pagination.

        Returns:
            data.affected_items: Groups with name, gid and members.
        """
        params = {k: v for k, v in {
            "group_name": group_name, "limit": limit, "offset": offset,
        }.items() if v is not None}
        return await client.get(f"/syscollector/{agent_id}/groups", params=params or None)

    @mcp.tool()
    async def get_agent_browser_extensions(
        agent_id: str,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> dict:
        """
        Lists browser extensions installed on an agent.

        Args:
            agent_id: Agent ID (e.g. '001').
            limit: Maximum number of results.
            offset: Offset for pagination.

        Returns:
            data.affected_items: Extensions with name, version, browser, enabled.
        """
        params = {k: v for k, v in {
            "limit": limit, "offset": offset,
        }.items() if v is not None}
        return await client.get(f"/syscollector/{agent_id}/browser_extensions", params=params or None)

    @mcp.tool()
    async def get_agent_services(
        agent_id: str,
        name: Optional[str] = None,
        display_name: Optional[str] = None,
        state: Optional[str] = None,
        start_type: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
    ) -> dict:
        """
        Lists system services on an agent (Windows SCM / systemd).

        Args:
            agent_id: Agent ID (e.g. '001').
            name: Filter by service name.
            display_name: Filter by display name.
            state: Filter by state (e.g. 'running', 'stopped').
            start_type: Filter by start type (e.g. 'auto', 'manual', 'disabled').
            limit: Maximum number of results.
            offset: Offset for pagination.
            sort: Field and order.
            search: Text search.
            select: Comma-separated fields to include.

        Returns:
            data.affected_items: Services with name, display_name, state, start_type, description.
        """
        params = {k: v for k, v in {
            "name": name, "display_name": display_name,
            "state": state, "start_type": start_type,
            "limit": limit, "offset": offset,
            "sort": sort, "search": search, "select": select,
        }.items() if v is not None}
        return await client.get(f"/syscollector/{agent_id}/services", params=params or None)
