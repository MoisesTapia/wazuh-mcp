from __future__ import annotations

from typing import Optional

from fastmcp import FastMCP

from ..client import WazuhClient
from ..sanitize import sanitize_output, wrap_external_content


def register(mcp: FastMCP, client: WazuhClient) -> None:

    @mcp.tool()
    @sanitize_output()
    async def run_logtest(
        event: str,
        log_format: str,
        location: str,
        token: Optional[str] = None,
    ) -> dict:
        """
        Tests a log against Wazuh rules and decoders (logtest).

        Useful for debugging rules and verifying how Wazuh parses an event
        before it reaches the production environment.

        Args:
            event: String containing the log to analyze (e.g. 'Dec 25 10:00:00 host sshd: Failed password').
            log_format: Log format. Values: 'syslog', 'json', 'snort-full',
                'squid', 'eventlog', 'eventchannel', 'audit', 'mysql_log', 'postgresql_log',
                'nmapg', 'iis', 'command', 'full_command', 'djb-multilog', 'multi-line'.
            location: Log source (e.g. '/var/log/auth.log', 'WinEvtLog').
            token: Existing session token to reuse analysis context.
                If omitted, a new session is created automatically.

        Returns:
            output with: token, messages (warnings/errors), output{rule, decoder,
                predecoder, data} with the analysis result.
        """
        body: dict = {
            "event": event,
            "log_format": log_format,
            "location": location,
        }
        if token is not None:
            body["token"] = token
        result = await client.put("/logtest", json=body)
        return wrap_external_content(result, source="wazuh_api/logtest")

    @mcp.tool()
    async def end_logtest_session(token: str) -> dict:
        """
        Closes a logtest session and releases associated resources.

        Args:
            token: Session token to close (obtained from run_logtest).

        Returns:
            Confirmation of session closure.
        """
        return await client.delete(f"/logtest/sessions/{token}")
