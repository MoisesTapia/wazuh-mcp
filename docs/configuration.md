# Configuration

All configuration lives in the `.env` file (loaded by `pydantic-settings`).
Copy `.env.example` to `.env` and adjust the values.

- [Credentials and access](#credentials-and-access)
- [Environment variables](#environment-variables)
- [Wazuh Indexer (SOC tools)](#wazuh-indexer-soc-tools)
- [MCP transport](#mcp-transport)
- [Changing passwords](#changing-passwords)

---

## Credentials and access

| Service | URL | User | Password |
|----------|-----|---------|-----------|
| **Dashboard** (web UI) | `https://localhost` | `admin` | `SecretPassword` |
| **REST API** (MCP and tools) | `https://localhost:55000` | `wazuh-wui` | `MyS3cr37P450r.*-` |
| **Indexer** (OpenSearch) | `https://localhost:9200` | `admin` | `SecretPassword` |
| **MCP HTTP** (if `mcp` profile) | `http://localhost:8000/mcp/` | Bearer token | `MCP_API_KEY` |

> These are **development** credentials — do not use them in production.
> See [Changing passwords](#changing-passwords) to harden them, and the
> [network exposure checklist](security.md#network-exposure--production-checklist)
> before making the stack reachable beyond `localhost`.

The MCP connects to the **REST API** with `wazuh-wui` / `MyS3cr37P450r.*-`.
Do **not** use the dashboard `admin` / `SecretPassword` for the MCP — those are
indexer credentials, not REST API credentials.

---

## Environment variables

### Wazuh Manager (REST API)

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_HOST` | `localhost` | Manager hostname |
| `WAZUH_PORT` | `55000` | REST API port |
| `WAZUH_USER` | — (required) | REST API user |
| `WAZUH_PASSWORD` | — (required) | REST API password |
| `WAZUH_VERIFY_SSL` | `true` | `false` for local dev, `true` in production |
| `WAZUH_CA_BUNDLE` | — | Path to a CA bundle PEM. When set, TLS is **always** verified and overrides `WAZUH_VERIFY_SSL` |
| `JWT_REFRESH_MARGIN` | `60` | Seconds before expiry to renew the JWT |
| `REQUEST_TIMEOUT` | `30` | HTTP timeout per request (seconds) |
| `MAX_RETRIES` | `3` | Retries with backoff on transient errors |

> **TLS warning:** setting `WAZUH_VERIFY_SSL=false` with a non-local
> `WAZUH_HOST` emits a runtime warning — it exposes credentials to MITM
> attacks. Use `WAZUH_VERIFY_SSL=true` or `WAZUH_CA_BUNDLE` in production.
> See [Security model](security.md#tls-verification).

### Audit / logging

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR` |
| `LOG_FILE` | — | Path to a rotating log file (in addition to stderr). Omit for stderr only |
| `AUDIT_ENABLED` | `true` | Set to `false` only in isolated test environments |

See [Security model](security.md#audit-logging) for the audit record format.

### Indexer (OpenSearch admin)

| Variable | Default | Description |
|----------|---------|-------------|
| `INDEXER_PASSWORD` | `SecretPassword` | Indexer `admin` password. Must match the hash in `config/wazuh_indexer/internal_users.yml` |

---

## Wazuh Indexer (SOC tools)

Wazuh 4.8.0+ stores alerts and vulnerabilities **only** in the Indexer
(port 9200) — the Manager REST API no longer exposes them. To enable the SOC
tools (`get_alerts`, `get_vulnerabilities`, `search_cve`, …) configure the
Indexer connection:

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_INDEXER_HOST` | — | Indexer hostname. **Enables the SOC tools** |
| `WAZUH_INDEXER_PORT` | `9200` | Indexer port |
| `WAZUH_INDEXER_USER` | `admin` | Indexer user |
| `WAZUH_INDEXER_PASSWORD` | `admin` | Indexer password |
| `WAZUH_INDEXER_VERIFY_SSL` | `false` | TLS verification for the Indexer |

If `WAZUH_INDEXER_HOST` is not set, the SOC tools degrade gracefully and return
a clear "not configured" message instead of failing. See [SOC & SOAR](soc.md).

---

## MCP transport

The server runs over `stdio` (local, for Claude Desktop) or `http` (Docker).

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_TRANSPORT` | `stdio` | `stdio` (local) or `http` (Docker/network) |
| `MCP_HOST` | `127.0.0.1` | Listening host in HTTP mode. Loopback-only by default; never `0.0.0.0` without a TLS proxy |
| `MCP_PORT` | `8000` | Port in HTTP mode |
| `MCP_API_KEY` | — | **Required in HTTP mode.** Bearer token clients must present. Generate with `openssl rand -hex 32` |

> In HTTP mode the server **refuses to start** without `MCP_API_KEY`. All
> requests except `/health` must carry `Authorization: Bearer <key>`.
> See [Security model](security.md#http-transport-authentication).

---

## Changing passwords

To change `SecretPassword` (indexer) or `MyS3cr37P450r.*-` (API):

1. **Indexer** (`SecretPassword`): the hash in
   `config/wazuh_indexer/internal_users.yml` must be regenerated with `bcrypt`.
   Use the container tool:
   ```bash
   docker exec -it wazuh.indexer /bin/bash
   /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh
   ```
   Copy the generated hash into `internal_users.yml` for the `admin` user, and
   update `INDEXER_PASSWORD` in `.env`.

2. **REST API** (`MyS3cr37P450r.*-`): change `WAZUH_PASSWORD` in `.env`.
   The Manager applies it on startup via `API_PASSWORD`.

3. Restart the stack:
   ```bash
   make docker-down && make docker-up
   ```

---

Next: [Claude integration](claude-integration.md) · [Security model](security.md)
