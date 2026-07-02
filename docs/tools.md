# Tools catalog

**206 tools** across 23 modules, plus the built-in `ping_wazuh`. Tools fall
into three groups:

- **Manager REST API** — agents, rules, cluster, RBAC, FIM, SCA, MITRE… (port 55000)
- **SOC (Indexer)** — alerts, CVEs and threat analysis (port 9200, requires `WAZUH_INDEXER_HOST`)
- **SOAR / Active Response** — block IPs, isolate agents, kill processes, YARA scans

For the SOC and SOAR tools in depth, see [SOC & SOAR](soc.md).

---

## Manager REST API tools

| Module | Tools | Description | Main operations |
|--------|------:|-------------|-----------------|
| `security` | 31 | RBAC and users | Users, roles, policies, RBAC rules, tokens, security config |
| `agents` | 30 | Agent management | List, create, restart, update, delete, assign groups, upgrade |
| `cluster` | 23 | Wazuh Cluster | Nodes, status, healthcheck, configuration, logs, statistics |
| `manager` | 18 | Wazuh Manager | Configuration, logs, statistics, status, validate config, restart |
| `syscollector` | 13 | Per-agent inventory | OS, hardware, packages, processes, ports, network, hotfixes |
| `experimental` | 12 | Multi-agent (experimental) | Hardware/OS/packages/processes/ports/network across all agents; bulk clears |
| `groups` | 8 | Agent groups | Create, delete, configure, list agents and group files |
| `rules` | 7 | Detection rules | List, files, groups, requirements (PCI-DSS, HIPAA, GDPR, NIST…) |
| `mitre` | 7 | MITRE ATT&CK | Techniques, tactics, APT groups, software, mitigations, references |
| `decoders` | 6 | Log decoders | List, files, parent decoders |
| `lists` | 5 | CDB lists | List, read, update and delete Constant Database lists |
| `syscheck` | 4 | File Integrity Monitoring | FIM results, last scan, clear, run scan |
| `rootcheck` | 4 | Rootkit detection | Results, last scan, clear, run scan |
| `observability` | 3 | MCP server health | `get_mcp_health`, `get_mcp_metrics`, `reset_circuit_breaker` |
| `sca` | 2 | Security Config Assessment | Evaluated CIS policies, individual checks (passed/failed) |
| `logtest` | 2 | Log testing | Test logs against rules/decoders, manage sessions |
| `active_response` | 1 | Active Response (raw) | Execute AR scripts on agents |
| `ciscat` | 1 | CIS-CAT | CIS-CAT results per agent (requires CIS-CAT license) |
| `events` | 1 | Ingest | Send events directly to the Manager |
| `overview` | 1 | Dashboard | Executive summary of all agents |
| `(built-in)` | 1 | Connectivity | `ping_wazuh` — check the Manager version |

## SOC tools (Wazuh Indexer)

| Module | Tools | Description |
|--------|------:|-------------|
| `soc_alerts` | 7 | Alerts, critical alerts, summaries, search, per-agent timeline, top threats, pattern analysis |
| `soc_vulnerabilities` | 5 | CVEs, critical CVEs, summaries, per-agent risk score, CVE search |

## SOAR tools (Active Response)

| Module | Tools | Description |
|--------|------:|-------------|
| `active_response_soc` | 14 | Block/unblock IPs, isolate/unisolate agents, kill processes, restart agents, YARA scans, custom AR, CDB updates, plus verification helpers |

> **Total: 206 tools** (205 in modules + `ping_wazuh`).

---

## Usage examples with Claude

### Infrastructure inventory and status

```
"Give me a summary of all my agents' status"
→ get_agents_overview, list_agents

"What operating system versions do my agents have?"
→ get_all_agents_os, get_agents_summary_os

"Show me the installed packages on agent 001"
→ get_agent_packages(agent_id="001")

"What ports are open on my servers?"
→ get_all_agents_ports(protocol="tcp", state="listening")

"Are there any disconnected agents?"
→ list_agents(status="disconnected")
```

### Security and compliance

```
"What is the CIS compliance score for my agents?"
→ get_sca_results(agent_id="001")

"Show me failed CIS checks on agent 001"
→ get_sca_policy_checks(agent_id="001", policy_id="cis_ubuntu20-04", result="failed")

"Are there any rootkits detected on any agent?"
→ get_rootcheck_results(agent_id="001", status="outstanding")

"What MITRE techniques are covered by Wazuh rules?"
→ list_mitre_techniques(), list_rules()
```

### SOC — alerts and vulnerabilities (Indexer)

```
"Show me the critical alerts from the last 6 hours"
→ get_critical_alerts(hours=6)

"What are the top threats across my fleet today?"
→ get_top_threats()

"Give me the risk score for agent 001"
→ get_agent_risk_score(agent_id="001")

"Is CVE-2024-3094 present anywhere in my environment?"
→ search_cve(cve_id="CVE-2024-3094")
```

### SOAR — active response

```
"Block IP 192.168.1.100 on agent 001"
→ wazuh_block_ip(agent_id="001", ip="192.168.1.100")

"Isolate agent 005 from the network"
→ isolate_agent(agent_id="005")

"Run a YARA scan on agent 003"
→ run_yara_scan(agent_id="003")

"Confirm the IP was actually blocked"
→ check_blocked_ip(agent_id="001", ip="192.168.1.100")
```

### Administration

```
"Create a user called 'analyst' with the read-only policy"
→ create_user(username="analyst", password="..."), list_policies(), add_policies_to_role(...)

"What is the Manager's active configuration?"
→ get_manager_active_configuration()

"Show me the last Manager logs"
→ get_manager_logs(limit=50)

"Is the cluster synchronized?"
→ get_cluster_ruleset_sync_status()

"Is the MCP server healthy?"
→ get_mcp_health()
```

---

Next: [SOC & SOAR](soc.md) · [Architecture](architecture.md)
