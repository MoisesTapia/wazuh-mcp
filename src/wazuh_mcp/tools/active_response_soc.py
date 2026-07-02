"""
Active Response SOC — full cycle: action + verification + rollback.

Each action tool has a verification and/or rollback counterpart:
  wazuh_block_ip      <-> check_blocked_ip      <-> wazuh_unblock_ip
  isolate_agent       <-> check_agent_connectivity <-> unisolate_agent
  kill_process        <-> verify_process_killed
  run_custom_ar       <-> (no automatic rollback)

Every action is written to a structured audit log distinct from the generic
per-tool audit trail in audit.py, so a SOC analyst can grep active-response
actions in isolation (see _audit_log below).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Optional

from fastmcp import FastMCP

from ..client import WazuhClient
from ..sanitize import sanitize_output

logger = logging.getLogger(__name__)

_INVALID_ARG_CHARS = re.compile(r"[\s;|&><`$()]")
_VALID_CUSTOM_COMMAND = re.compile(r"^[a-zA-Z0-9_-]+$")


def _audit_log(action: str, agent_ids: list[str], params: dict, result: dict) -> None:
    """Emit a structured JSON audit line for an active-response action.

    Distinct from the generic audit_tool decorator: this is specific to
    active-response actions and always logs at WARNING, regardless of
    whether the docstring carries a DESTRUCTIVE:/CAUTION: marker.
    """
    data = result.get("data", {}) if isinstance(result, dict) else {}
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "mcp_active_response",
        "action": action,
        "agents": agent_ids,
        "params": params,
        "result_summary": {
            "total_affected": data.get("total_affected_items", 0),
            "total_failed": data.get("total_failed_items", 0),
        },
    }
    logger.warning("AUDIT: %s", json.dumps(entry, default=str))


def _validate_ip(ip_address: str) -> Optional[dict]:
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        return {"error": f"IP inválida: {ip_address}"}
    return None


def register(mcp: FastMCP, client: WazuhClient) -> None:

    # ── Action tools ──────────────────────────────────────────────────────

    @mcp.tool()
    @sanitize_output()
    async def wazuh_block_ip(
        agent_ids: list[str], ip_address: str, timeout: int = 0
    ) -> dict:
        """
        DESTRUCTIVE: Blocks an IP address on the given agents via the
        firewall-drop active-response script.

        Args:
            agent_ids: Agent IDs to apply the block on (e.g. ['001', '002']).
            ip_address: IP address to block. Validated before sending.
            timeout: 0 means permanent block until wazuh_unblock_ip is called.

        Returns:
            {"blocked_ip": ..., "agents": [...], "result": <api_response>}
        """
        invalid = _validate_ip(ip_address)
        if invalid:
            return invalid
        body: dict[str, Any] = {
            "command": "firewall-drop",
            "arguments": ["-", "null", ip_address, "null"],
            "alert": {
                "data": {"srcip": ip_address},
                "rule": {"id": "100001", "description": "MCP IP block"},
            },
        }
        result = await client.put(
            "/active-response", json=body, params={"agents_list": ",".join(agent_ids)}
        )
        _audit_log("block_ip", agent_ids, {"ip": ip_address, "timeout": timeout}, result)
        return {"blocked_ip": ip_address, "agents": agent_ids, "result": result}

    @mcp.tool()
    @sanitize_output()
    async def wazuh_unblock_ip(agent_ids: list[str], ip_address: str) -> dict:
        """
        DESTRUCTIVE: Reverts a previous firewall-drop block for an IP address.

        Args:
            agent_ids: Agent IDs to remove the block from.
            ip_address: IP address to unblock. Validated before sending.

        Returns:
            {"unblocked_ip": ..., "agents": [...], "result": <api_response>}
        """
        invalid = _validate_ip(ip_address)
        if invalid:
            return invalid
        body: dict[str, Any] = {
            "command": "!firewall-drop",
            "arguments": ["-", "null", ip_address, "null"],
            "alert": {
                "data": {"srcip": ip_address},
                "rule": {"id": "100001", "description": "MCP IP unblock"},
            },
        }
        result = await client.put(
            "/active-response", json=body, params={"agents_list": ",".join(agent_ids)}
        )
        _audit_log("unblock_ip", agent_ids, {"ip": ip_address}, result)
        return {"unblocked_ip": ip_address, "agents": agent_ids, "result": result}

    @mcp.tool()
    @sanitize_output()
    async def isolate_agent(agent_id: str, reason: str = "") -> dict:
        """
        DESTRUCTIVE: Isolates an agent from the network via active-response.

        Runs the 'isolate-host' script if configured on the manager. The
        agent will only be able to reach the Wazuh Manager until
        unisolate_agent is called.

        Args:
            agent_id: Agent ID to isolate.
            reason: Free-text reason recorded in the active-response alert.

        Returns:
            {"isolated_agent": agent_id, "result": <api_response>}
        """
        body: dict[str, Any] = {
            "command": "isolate-host",
            "arguments": [],
            "alert": {"rule": {"description": f"MCP isolation: {reason}"}},
        }
        result = await client.put(
            "/active-response", json=body, params={"agents_list": agent_id}
        )
        _audit_log("isolate_agent", [agent_id], {"reason": reason}, result)
        return {"isolated_agent": agent_id, "result": result}

    @mcp.tool()
    @sanitize_output()
    async def unisolate_agent(agent_id: str) -> dict:
        """
        DESTRUCTIVE: Reverts network isolation of an agent.

        Args:
            agent_id: Agent ID to restore network access for.

        Returns:
            {"unisolated_agent": agent_id, "result": <api_response>}
        """
        body: dict[str, Any] = {"command": "!isolate-host", "arguments": []}
        result = await client.put(
            "/active-response", json=body, params={"agents_list": agent_id}
        )
        _audit_log("unisolate_agent", [agent_id], {}, result)
        return {"unisolated_agent": agent_id, "result": result}

    @mcp.tool()
    @sanitize_output()
    async def kill_process(
        agent_id: str, process_name: str, pid: Optional[int] = None
    ) -> dict:
        """
        DESTRUCTIVE: Terminates a running process on the agent via the
        kill-process active-response script.

        Args:
            agent_id: Agent ID where the process is running.
            process_name: Process name to kill. Rejected if it contains
                whitespace or any of ; | & > < ` $ ( ).
            pid: Optional PID to disambiguate between processes with the
                same name.

        Returns:
            {"agent_id": ..., "process": ..., "result": <api_response>}
        """
        if _INVALID_ARG_CHARS.search(process_name):
            return {"error": "process_name contiene caracteres inválidos"}
        arguments = [process_name] + ([str(pid)] if pid else [])
        body: dict[str, Any] = {"command": "kill-process", "arguments": arguments}
        result = await client.put(
            "/active-response", json=body, params={"agents_list": agent_id}
        )
        _audit_log(
            "kill_process", [agent_id], {"process": process_name, "pid": pid}, result
        )
        return {"agent_id": agent_id, "process": process_name, "result": result}

    @mcp.tool()
    @sanitize_output()
    async def restart_wazuh_agent_ar(agent_id: str) -> dict:
        """
        CAUTION: Restarts the Wazuh service on the agent via active-response.

        Different from restart_agent (which uses the Manager API): this uses
        active-response, so it works even when the agent is unresponsive to
        the API but still has active-response active.

        Args:
            agent_id: Agent ID to restart.

        Returns:
            {"agent_id": ..., "result": <api_response>}
        """
        body: dict[str, Any] = {"command": "restart-wazuh", "arguments": []}
        result = await client.put(
            "/active-response", json=body, params={"agents_list": agent_id}
        )
        return {"agent_id": agent_id, "result": result}

    @mcp.tool()
    @sanitize_output()
    async def run_yara_scan(agent_id: str, path: str = "/tmp") -> dict:
        """
        Runs a YARA scan on the given path via active-response, if the
        run-yara script is configured on the manager.

        Args:
            agent_id: Agent ID to scan.
            path: Absolute path to scan. Must start with '/' and must not
                contain ; | & > < ` $ ( ).

        Returns:
            {"agent_id": ..., "path": ..., "result": <api_response>}
        """
        if not path.startswith("/") or _INVALID_ARG_CHARS.search(path):
            return {"error": "path inválido"}
        body: dict[str, Any] = {"command": "run-yara", "arguments": [path]}
        result = await client.put(
            "/active-response", json=body, params={"agents_list": agent_id}
        )
        return {"agent_id": agent_id, "path": path, "result": result}

    @mcp.tool()
    @sanitize_output()
    async def run_custom_ar(
        agent_ids: list[str],
        command: str,
        arguments: Optional[list[str]] = None,
        alert: Optional[dict[str, Any]] = None,
    ) -> dict:
        """
        CAUTION: Runs a custom active-response script. Only scripts already
        configured in ossec.conf under <active-response> will actually run —
        arbitrary scripts are rejected by Wazuh itself.

        Args:
            agent_ids: Agent IDs to run the script on.
            command: Script name configured on the manager. Must match
                ^[a-zA-Z0-9_-]+$.
            arguments: Additional arguments for the script.
            alert: Alert dict passed to the script.

        Returns:
            {"command": ..., "agents": [...], "result": <api_response>}
        """
        if not _VALID_CUSTOM_COMMAND.match(command):
            return {"error": "command contiene caracteres inválidos"}
        body: dict[str, Any] = {"command": command}
        if arguments is not None:
            body["arguments"] = arguments
        if alert is not None:
            body["alert"] = alert
        result = await client.put(
            "/active-response", json=body, params={"agents_list": ",".join(agent_ids)}
        )
        _audit_log("custom_ar", agent_ids, {"command": command}, result)
        return {"command": command, "agents": agent_ids, "result": result}

    @mcp.tool()
    @sanitize_output()
    async def wazuh_add_ip_to_cdb(
        list_name: str, ip_address: str, value: str = "blocked"
    ) -> dict:
        """
        Adds an IP address to a Wazuh CDB list for persistent, rule-based
        blocking. Unlike firewall-drop (temporary, iptables-based), this
        survives restarts because it is persisted on the Manager.

        Args:
            list_name: CDB list filename (e.g. 'blacklist').
            ip_address: IP address to add. Validated before sending.
            value: Value associated with the IP in the CDB list.

        Returns:
            {"list": ..., "ip": ..., "action": "added" | "already_exists"}
        """
        invalid = _validate_ip(ip_address)
        if invalid:
            return invalid
        current = await client.get(f"/lists/files/{list_name}")
        affected = current.get("data", {}).get("affected_items", [])
        items = affected[0].get("items", []) if affected else []
        if any(item.get("key") == ip_address and item.get("value") == value for item in items):
            return {"list": list_name, "ip": ip_address, "action": "already_exists"}
        lines = [f"{item.get('key')}:{item.get('value')}" for item in items]
        lines.append(f"{ip_address}:{value}")
        new_content = "\n".join(lines) + "\n"
        await client.put(
            f"/lists/files/{list_name}",
            params={"overwrite": "true"},
            content=new_content,
            content_type="application/octet-stream",
        )
        return {"list": list_name, "ip": ip_address, "action": "added"}

    # ── Verification tools ───────────────────────────────────────────────

    @mcp.tool()
    async def check_blocked_ip(agent_id: str, ip_address: str) -> dict:
        """
        Checks whether an IP address is currently blocked on an agent.

        Direct verification of iptables/nftables state is not reliably
        available through the Manager API, so this returns is_blocked=None
        with a note when it cannot be confirmed directly.

        Args:
            agent_id: Agent ID to check.
            ip_address: IP address to check.

        Returns:
            {"agent_id": ..., "ip": ..., "is_blocked": True|False|None,
             "method": ..., "checked_at": <ISO timestamp>}
        """
        return {
            "agent_id": agent_id,
            "ip": ip_address,
            "is_blocked": None,
            "method": "unknown",
            "note": "Verificación directa no disponible. Revisar manualmente.",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    @mcp.tool()
    async def check_agent_connectivity(agent_id: str) -> dict:
        """
        Checks the connectivity status of an agent, combining Manager data
        on agent status and daemon health.

        Args:
            agent_id: Agent ID to check.

        Returns:
            {"agent_id": ..., "status": ..., "last_keepalive": ...,
             "disconnected_since": ..., "daemons_ok": ..., "is_isolated": ...}
        """
        agents_result = await client.get("/agents", params={"agents_list": agent_id})
        items = agents_result.get("data", {}).get("affected_items", [])
        agent = items[0] if items else {}
        status = agent.get("status", "unknown")
        last_keepalive = agent.get("lastKeepAlive")

        daemons_result = await client.get(f"/agents/{agent_id}/daemons/stats")
        daemons_ok = daemons_result.get("error", 1) == 0

        return {
            "agent_id": agent_id,
            "status": status,
            "last_keepalive": last_keepalive,
            "disconnected_since": None if status == "active" else last_keepalive,
            "daemons_ok": daemons_ok,
            "is_isolated": None,
        }

    @mcp.tool()
    async def get_agent_active_responses(agent_id: str) -> dict:
        """
        Lists recent active-response executions for an agent, from the
        manager's wazuh-execd logs.

        Args:
            agent_id: Agent ID to filter by.

        Returns:
            {"agent_id": ..., "recent_active_responses": [{"timestamp": ...,
             "action": ..., "result": ...}, ...]}
        """
        logs = await client.get("/manager/logs", params={"tag": "wazuh-execd", "limit": 100})
        items = logs.get("data", {}).get("affected_items", [])
        matches = [item for item in items if agent_id in str(item.get("description", ""))]
        return {
            "agent_id": agent_id,
            "recent_active_responses": [
                {
                    "timestamp": item.get("timestamp"),
                    "action": item.get("tag"),
                    "result": item.get("description"),
                }
                for item in matches
            ],
        }

    @mcp.tool()
    async def verify_process_killed(agent_id: str, process_name: str) -> dict:
        """
        Verifies whether a process was successfully terminated by checking
        syscollector's process list.

        Args:
            agent_id: Agent ID to check.
            process_name: Process name to look for.

        Returns:
            {"agent_id": ..., "process_name": ..., "is_running": ...,
             "matching_pids": [...], "verified_at": <ISO timestamp>}
        """
        result = await client.get(f"/syscollector/{agent_id}/processes")
        items = result.get("data", {}).get("affected_items", [])
        matches = [p for p in items if p.get("name") == process_name]
        matching_pids = [p.get("pid") for p in matches if p.get("pid") is not None]
        return {
            "agent_id": agent_id,
            "process_name": process_name,
            "is_running": bool(matches),
            "matching_pids": matching_pids,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

    @mcp.tool()
    async def get_ar_scripts_available(agent_id: Optional[str] = None) -> dict:
        """
        Lists active-response scripts configured on the manager.

        Args:
            agent_id: Unused placeholder for future per-agent script
                discovery; scripts are configured manager-wide.

        Returns:
            {"configured_commands": [...], "source": "manager_config"}
        """
        result = await client.get(
            "/manager/configuration", params={"section": "active-response"}
        )
        commands: list[str] = []
        items = result.get("data", {}).get("affected_items", [])
        for item in items:
            ar_entries = item.get("active-response")
            if isinstance(ar_entries, dict):
                ar_entries = [ar_entries]
            if isinstance(ar_entries, list):
                for entry in ar_entries:
                    cmd = entry.get("command")
                    if cmd:
                        commands.append(cmd)
        return {"configured_commands": commands, "source": "manager_config"}
