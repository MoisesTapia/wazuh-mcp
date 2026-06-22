"""Tests for the audit logging system (audit.py)."""
from __future__ import annotations

import json
import logging

import pytest

from wazuh_mcp.audit import AuditLogger, audit_tool, configure_audit
from wazuh_mcp.config import WazuhSettings


# ── Helpers ───────────────────────────────────────────────────────────────────


def _audit_settings(**overrides) -> WazuhSettings:
    """Build a WazuhSettings instance suitable for audit tests."""
    base = dict(
        wazuh_user="u",
        wazuh_password="p",
        wazuh_host="localhost",
        wazuh_port=55000,
        wazuh_verify_ssl=False,
        audit_enabled=True,
        log_level="DEBUG",
        log_file=None,
    )
    base.update(overrides)
    return WazuhSettings(**base)


def _audit_records(caplog) -> list[dict]:
    """Return parsed JSON records emitted by the 'wazuh_mcp.audit' logger."""
    return [
        json.loads(r.getMessage())
        for r in caplog.records
        if r.name == "wazuh_mcp.audit"
    ]


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def setup_audit():
    """
    Configure the audit logger before each test and allow pytest's caplog
    fixture to capture its output via log propagation.
    """
    configure_audit(_audit_settings())
    audit_log = logging.getLogger("wazuh_mcp.audit")
    original_propagate = audit_log.propagate
    audit_log.propagate = True
    yield
    audit_log.propagate = original_propagate


# ── Tests ─────────────────────────────────────────────────────────────────────


async def test_successful_tool_logs_required_fields(caplog):
    """A successful tool call emits one record with all mandatory fields."""

    @audit_tool
    async def list_agents(status: str = "active", limit: int = 10) -> dict:
        """Lists registered agents."""
        return {"data": []}

    with caplog.at_level(logging.DEBUG, logger="wazuh_mcp.audit"):
        await list_agents(status="disconnected", limit=5)

    records = _audit_records(caplog)
    assert len(records) == 1, f"Expected 1 audit record, got {len(records)}"

    rec = records[0]
    assert rec["tool"] == "list_agents"
    assert rec["outcome"] == "success"
    assert rec["params"] == {"status": "disconnected", "limit": 5}
    assert rec["destructive"] is False
    assert isinstance(rec["duration_ms"], int)
    assert rec["duration_ms"] >= 0
    # ISO 8601 timestamp must be present
    assert "ts" in rec
    assert "T" in rec["ts"] and rec["ts"].endswith("Z")


async def test_failed_tool_logs_error_outcome_and_type(caplog):
    """A tool that raises emits outcome=error, error_type, and re-raises."""

    @audit_tool
    async def get_agent(agent_id: str) -> dict:
        """Returns agent information."""
        raise ConnectionError("timed out reaching Wazuh")

    with caplog.at_level(logging.DEBUG, logger="wazuh_mcp.audit"):
        with pytest.raises(ConnectionError):
            await get_agent(agent_id="042")

    records = _audit_records(caplog)
    assert len(records) == 1

    rec = records[0]
    assert rec["tool"] == "get_agent"
    assert rec["outcome"] == "error"
    assert rec["error_type"] == "ConnectionError"
    assert "timed out" in rec["error"]
    assert isinstance(rec["duration_ms"], int)
    # Error records must be at ERROR level
    assert caplog.records[-1].levelno == logging.ERROR


async def test_sensitive_parameter_is_redacted(caplog):
    """Parameters whose names match the sensitive pattern appear as [REDACTED]."""

    @audit_tool
    async def create_user(username: str, password: str, api_key: str) -> dict:
        """Creates an RBAC user."""
        return {"created": True}

    with caplog.at_level(logging.DEBUG, logger="wazuh_mcp.audit"):
        await create_user(username="alice", password="S3cr3t!", api_key="tok-abc123")

    rec = _audit_records(caplog)[0]
    params = rec["params"]

    assert params["username"] == "alice", "Non-sensitive field must pass through unchanged"
    assert params["password"] == "[REDACTED]", "Field named 'password' must be redacted"
    assert params["api_key"] == "[REDACTED]", "Field containing 'key' must be redacted"


async def test_destructive_tool_sets_flag_and_warning_level(caplog):
    """A tool with DESTRUCTIVE: in its docstring logs at WARNING with destructive=true."""

    @audit_tool
    async def delete_agents(agents_list: str, status: str) -> dict:
        """
        Permanently deletes agents from Wazuh.

        DESTRUCTIVE: This operation cannot be undone.

        Args:
            agents_list: Comma-separated IDs or 'all'.
            status: Required status ('all', 'disconnected', …).
        """
        return {"deleted": 2}

    with caplog.at_level(logging.DEBUG, logger="wazuh_mcp.audit"):
        await delete_agents(agents_list="001,002", status="disconnected")

    records = _audit_records(caplog)
    assert len(records) == 1

    rec = records[0]
    assert rec["destructive"] is True
    assert rec["outcome"] == "success"

    # Destructive tools must log at WARNING, not INFO
    audit_log_records = [r for r in caplog.records if r.name == "wazuh_mcp.audit"]
    assert audit_log_records[0].levelno == logging.WARNING
