# Claude integration

The MCP server works with Claude Desktop and Claude Code, over `stdio` (local)
or `http` (Docker).

- [Claude Desktop — automatic](#claude-desktop--automatic)
- [Claude Desktop — manual](#claude-desktop--manual)
- [Claude Code](#claude-code)

---

## Claude Desktop — automatic

```bash
source .venv/bin/activate
make setup-claude-desktop
# → Restart Claude Desktop
```

This writes the correct entry into the Claude Desktop config file for you.

---

## Claude Desktop — manual

Edit the Claude Desktop configuration file:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

### Option A — Local MCP (stdio)

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "/ABSOLUTE/PATH/wazuh-mcp/.venv/bin/fastmcp",
      "args": ["run", "src/wazuh_mcp/server.py"],
      "cwd": "/ABSOLUTE/PATH/wazuh-mcp",
      "env": {
        "WAZUH_HOST": "localhost",
        "WAZUH_PORT": "55000",
        "WAZUH_USER": "wazuh-wui",
        "WAZUH_PASSWORD": "MyS3cr37P450r.*-",
        "WAZUH_VERIFY_SSL": "false",
        "WAZUH_INDEXER_HOST": "localhost",
        "WAZUH_INDEXER_PASSWORD": "SecretPassword"
      }
    }
  }
}
```

> `WAZUH_INDEXER_HOST` is optional — include it to enable the SOC tools
> (alerts, CVEs). See [SOC & SOAR](soc.md).

### Option B — MCP in Docker (HTTP)

Requires `make mcp-docker` and an `MCP_API_KEY`. See
[Configuration](configuration.md#mcp-transport).

```json
{
  "mcpServers": {
    "wazuh": {
      "url": "http://localhost:8000/mcp/",
      "headers": { "Authorization": "Bearer <your-mcp-api-key>" }
    }
  }
}
```

---

## Claude Code

From the project root with the venv active:

```bash
source .venv/bin/activate

fastmcp install claude-code src/wazuh_mcp/server.py \
  --name wazuh \
  --env-file .env \
  --with-editable .
```

Or in HTTP mode (if using `make mcp-docker`), add to your project's
`.claude/settings.json`:

```json
{
  "mcpServers": {
    "wazuh": {
      "url": "http://localhost:8000/mcp/",
      "headers": { "Authorization": "Bearer <your-mcp-api-key>" }
    }
  }
}
```

---

If Claude does not detect the MCP, see
[Troubleshooting](troubleshooting.md#claude-desktop-does-not-detect-the-mcp).
