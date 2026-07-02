# Troubleshooting

- [Certificates not found on `make docker-up`](#certificates-not-found-on-make-docker-up)
- [Indexer not starting / `unhealthy`](#indexer-not-starting--unhealthy)
- [Dashboard shows indexer connection error](#dashboard-shows-indexer-connection-error)
- [401 error when calling tools](#401-error-when-calling-tools)
- [SOC tools return "not configured"](#soc-tools-return-not-configured)
- [Circuit breaker is OPEN](#circuit-breaker-is-open)
- [Claude Desktop does not detect the MCP](#claude-desktop-does-not-detect-the-mcp)
- [HTTP mode refuses to start](#http-mode-refuses-to-start)
- [Start fresh (`make docker-reset`)](#start-fresh-make-docker-reset)
- [Integration tests fail with `Connection refused`](#integration-tests-fail-with-connection-refused)
- [`make lint` fails with Xcode error (macOS)](#make-lint-fails-with-xcode-error-macos)

---

## Certificates not found on `make docker-up`

```
ERROR: SSL certificates not found in config/wazuh_indexer_ssl_certs/
Run first: make certs
```

**Fix:**
```bash
make certs
make docker-up
```

---

## Indexer not starting / `unhealthy`

The indexer (OpenSearch) is the most demanding service. It needs:

1. At least 4 GB of RAM available for Docker.
2. On Linux: `vm.max_map_count >= 262144`.

```bash
# View indexer logs
docker compose logs wazuh.indexer

# Verify it responds (may take 2-3 min)
curl -sk -u admin:SecretPassword https://localhost:9200/_cluster/health

# On Linux, adjust the kernel setting
sudo sysctl -w vm.max_map_count=262144
```

If Docker Desktop has little RAM assigned, raise it in
Settings → Resources → Memory to at least 8 GB.

---

## Dashboard shows indexer connection error

The dashboard needs the indexer to be healthy. The first startup can take 3-4
minutes.

```bash
make docker-status
make wait-for-wazuh
```

---

## 401 error when calling tools

The credentials in `.env` don't match those in `docker-compose.yml`.

With this repo's stack, `.env` must have:

```env
WAZUH_USER=wazuh-wui
WAZUH_PASSWORD=MyS3cr37P450r.*-
```

Do **not** use `admin` / `SecretPassword` for the MCP — those are indexer
(dashboard) credentials, not REST API credentials. See
[Configuration](configuration.md#credentials-and-access).

---

## SOC tools return "not configured"

`get_alerts`, `get_vulnerabilities`, `search_cve`, etc. return:

```json
{ "error": "Wazuh Indexer no configurado", "not_configured": true }
```

They need the Indexer connection. Add to `.env`:

```env
WAZUH_INDEXER_HOST=localhost
WAZUH_INDEXER_PASSWORD=SecretPassword
```

See [SOC & SOAR](soc.md#enabling-the-soc-tools).

---

## Circuit breaker is OPEN

Tools fail immediately with `CircuitBreakerOpen` — the client saw 5+
consecutive connectivity failures and is failing fast.

1. Confirm the Manager is reachable again:
   ```bash
   curl -sk -u wazuh-wui:'MyS3cr37P450r.*-' https://localhost:55000/
   ```
2. Wait for the automatic recovery window (~60 s), or reset it explicitly by
   calling the `reset_circuit_breaker` tool from Claude.

See [Security model](security.md#circuit-breaker).

---

## Claude Desktop does not detect the MCP

1. Validate the config JSON (syntax errors fail silently):
   ```bash
   cat "~/Library/Application Support/Claude/claude_desktop_config.json" | python3 -m json.tool
   ```
2. Check the venv path is correct and absolute:
   ```bash
   ls /ABSOLUTE/PATH/wazuh-mcp/.venv/bin/fastmcp
   ```
3. Test the server manually:
   ```bash
   source .venv/bin/activate
   fastmcp run src/wazuh_mcp/server.py    # should start without errors
   ```
4. Fully restart Claude Desktop (Cmd+Q on macOS — don't just close the window).

---

## HTTP mode refuses to start

```
ValueError: MCP_API_KEY is required in HTTP mode.
```

In `http` transport the server needs a Bearer key. Generate and set one:

```bash
openssl rand -hex 32          # copy the output
# in .env:
MCP_TRANSPORT=http
MCP_API_KEY=<paste-here>
```

See [Configuration](configuration.md#mcp-transport) and
[Security model](security.md#http-transport-authentication).

---

## Start fresh (`make docker-reset`)

```bash
make docker-reset       # asks for confirmation, deletes ALL data (volumes)
make certs              # regenerate certificates (optional; previous still valid)
make docker-up
```

---

## Integration tests fail with `Connection refused`

The stack must be running before the tests:

```bash
make docker-up          # wait until it prints "✓ Wazuh API available"
make test-integration
```

---

## `make lint` fails with Xcode error (macOS)

```bash
# Direct alternative, without make
source .venv/bin/activate
python -m py_compile src/wazuh_mcp/server.py && echo OK
```

---

Back to [documentation index](README.md).
