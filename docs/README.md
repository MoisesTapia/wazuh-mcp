# Wazuh MCP Server — Documentation

Topic-based documentation for the Wazuh MCP Server. Start with the
[project README](../README.md) for an overview, then dive into the guide you need.

## Getting started

- [Installation](installation.md) — Requirements, quick start, SSL certificates, Docker stack.
- [Configuration](configuration.md) — Environment variables, credentials, changing passwords.
- [Claude integration](claude-integration.md) — Claude Desktop and Claude Code setup.

## Using the server

- [Tools catalog](tools.md) — All 206 tools grouped by module, with usage examples.
- [SOC & SOAR](soc.md) — Alerts, CVEs, threat analysis and active response.

## Under the hood

- [Security model](security.md) — Audit log, circuit breaker, sanitization, HTTP auth, TLS.
- [Architecture](architecture.md) — Request flow, module layout, Docker dependencies.

## Contributing & operations

- [Development](development.md) — Tests, adding modules, code conventions.
- [DevSecOps](devsecops.md) — Security scanning in CI and locally (pip-audit, pip-licenses, bandit, hadolint).
- [Makefile reference](makefile.md) — Every `make` target explained.
- [Troubleshooting](troubleshooting.md) — Common errors and fixes.
