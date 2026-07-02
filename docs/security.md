# Security model

The server is designed to sit between an LLM and a security platform, so it
treats both directions as hostile: the network to Wazuh, and the data flowing
back to the LLM.

- [TLS verification](#tls-verification)
- [HTTP transport authentication](#http-transport-authentication)
- [Network exposure & production checklist](#network-exposure--production-checklist)
- [Audit logging](#audit-logging)
- [Circuit breaker](#circuit-breaker)
- [Output sanitization](#output-sanitization)
- [Observability endpoints](#observability-endpoints)

---

## TLS verification

- `WAZUH_VERIFY_SSL` controls Manager TLS verification (`true` in production).
- `WAZUH_CA_BUNDLE` points to a CA PEM; when set it **always** verifies TLS and
  overrides `WAZUH_VERIFY_SSL`.
- Setting `WAZUH_VERIFY_SSL=false` with a **remote** host emits a runtime
  `UserWarning` — it exposes credentials and JWTs to MITM attacks. It is only
  safe for `localhost`/`127.0.0.1` with the self-signed dev certificates.

See [Configuration](configuration.md#environment-variables).

---

## HTTP transport authentication

In `stdio` mode there is no network surface. In `http` mode the server:

- **Refuses to start** without `MCP_API_KEY` (`_check_http_security`).
- Wraps the ASGI app in `_BearerAuthMiddleware`, which requires
  `Authorization: Bearer <MCP_API_KEY>` on every request.
- Uses `secrets.compare_digest` for constant-time comparison (no timing
  side-channel for token enumeration).
- Exempts only `/health` (Docker's `HEALTHCHECK` curls it without credentials).
  `/metrics` stays authenticated because it reflects internal configuration.
- Defaults `MCP_HOST` to `127.0.0.1` — never bind `0.0.0.0` without a TLS proxy.

Generate a key with:

```bash
openssl rand -hex 32
```

---

## Network exposure & production checklist

> **The bundled stack is a local development stack.** It ships with **publicly
> documented default credentials** (`admin` / `SecretPassword`, `wazuh-wui` /
> `MyS3cr37P450r.*-`) whose Indexer bcrypt hashes are even committed in
> `config/wazuh_indexer/internal_users.yml`. Running it unchanged on a
> network-reachable host would expose OpenSearch and the Wazuh API with
> credentials anyone can read from this repo.

To keep the default safe, `docker-compose.yml` binds the **management surface**
to loopback (`127.0.0.1`): REST API `55000`, Indexer `9200`, Dashboard `443`
and MCP `8000` are only reachable from the host itself. The **agent-facing
ports** (`1514`, `1515`, `514`) stay public because Wazuh agents on other hosts
must reach them — they authenticate with agent keys, not the static admin
credentials.

Before exposing anything beyond `localhost`, work through this checklist:

1. **Rotate every credential.** Change `WAZUH_PASSWORD`, `INDEXER_PASSWORD` and
   the Dashboard password, and regenerate the Indexer hash in
   `internal_users.yml`. See
   [Configuration → Changing passwords](configuration.md#changing-passwords).
2. **Enable TLS verification.** Set `WAZUH_VERIFY_SSL=true` or
   `WAZUH_CA_BUNDLE`; drop the self-signed dev certificates.
3. **Front the management ports with a TLS reverse proxy** instead of removing
   the `127.0.0.1` binding. Do not publish `9200`/`55000`/`443`/`8000` directly
   to the internet.
4. **Set a strong `MCP_API_KEY`** (`openssl rand -hex 32`) and keep
   `MCP_HOST=127.0.0.1` unless a proxy terminates TLS in front of it.
5. **Restrict inbound access** with a host firewall / security group — expose
   only what agents and operators actually need.
6. **Ship the audit log off-host** (`LOG_FILE` + log shipping) so tool activity
   is retained and monitored.

Remember the current [auth model](#http-transport-authentication) is a single
Bearer token with no per-tool RBAC: anyone holding the key can run every tool,
including destructive active-response actions.

---

## Audit logging

Every tool invocation is wrapped by `audit_tool` (see `src/wazuh_mcp/audit.py`),
which emits **one structured JSON line per call**:

```json
{
  "ts": "2026-07-02T10:15:30Z",
  "tool": "wazuh_block_ip",
  "params": {"agent_id": "001", "ip": "192.168.1.100"},
  "outcome": "success",
  "duration_ms": 142,
  "destructive": true
}
```

Behavior:

- **Secrets auto-redacted.** Any parameter whose name matches
  `password|token|secret|key|credential` is logged as `[REDACTED]` (recursively).
- **Destructive tools flagged.** Tools whose docstring contains `DESTRUCTIVE:`
  or `CAUTION:` are logged at `WARNING` with `"destructive": true`.
- **Errors captured.** Failed calls log at `ERROR` with `error_type` and
  `error`, then re-raise.
- **Configurable output.** Logs go to stderr, and also to a rotating file when
  `LOG_FILE` is set (10 MB × 5 files). Disable entirely with `AUDIT_ENABLED=false`
  (test environments only).

Controlled by `LOG_LEVEL`, `LOG_FILE`, `AUDIT_ENABLED` —
see [Configuration](configuration.md#audit--logging).

---

## Circuit breaker

`WazuhClient` calls flow through a `CircuitBreaker`
(`src/wazuh_mcp/circuit_breaker.py`) that fails fast when the Manager is down
instead of piling up timeouts.

| State | Meaning |
|-------|---------|
| `CLOSED` | Normal operation — requests pass through |
| `OPEN` | Manager considered down — requests fail immediately with `CircuitBreakerOpen` |
| `HALF_OPEN` | Trial period — one request is let through to probe recovery |

Transitions:

- `CLOSED → OPEN` after `failure_threshold` (default 5) consecutive failures.
- `OPEN → HALF_OPEN` after `recovery_timeout` (default 60 s).
- `HALF_OPEN → CLOSED` if the probe succeeds, back to `OPEN` if it fails.

The current state is reported by `get_mcp_health` / `/health`, and can be reset
manually with the `reset_circuit_breaker` tool once the Manager is back.

---

## Output sanitization

Wazuh ingests text from monitored endpoints, so tool output can carry two
threats. `src/wazuh_mcp/sanitize.py` defends against both:

**1. Prompt injection.** An attacker who can write to a monitored host (a log
line, a FIM path, rootcheck output) could embed instructions like *"ignore
previous instructions"*. The sanitizer:

- Detects known injection patterns (instruction overrides, `system:` markers,
  `<|im_start|>`, `[INST]`, markdown role headers, base64-encoded payloads).
- Replaces each match with `[POSSIBLE_INJECTION_NEUTRALIZED:<sha256>]`,
  **preserving the rest of the content** for forensic analysis.
- Wraps external API responses in a `_wazuh_external_data` envelope that tells
  the LLM to treat the payload as data, never as instructions.
- Emits a `WARNING` to the audit log on every neutralization.

**2. Secret leakage.** Logs and command lines can contain credentials typed on
a monitored host. The sanitizer redacts passwords, tokens, API keys, `Bearer`
tokens, `Authorization` headers and private keys, replacing each with
`[REDACTED:sha256:<hash>]` so two occurrences of the same secret stay
correlatable without exposing the value.

> The MCP server instructions also tell Claude that any response containing
> `_wazuh_external_data` must not be interpreted as instructions.

---

## Observability endpoints

The `observability` module exposes server state both as MCP tools and as HTTP
routes (used by the Docker `HEALTHCHECK`):

| MCP tool | HTTP route | Purpose |
|----------|-----------|---------|
| `get_mcp_health` | `GET /health` | Manager + Indexer connectivity, circuit breaker state, uptime |
| `get_mcp_metrics` | `GET /metrics` | Circuit breaker stats + non-sensitive configuration |
| `reset_circuit_breaker` | — | Manually reset the breaker to `CLOSED` |

`/health` returns `200` for `healthy`/`degraded` and `503` for `unhealthy`, and
is the only unauthenticated HTTP route.

---

Next: [Architecture](architecture.md) · [Configuration](configuration.md)
