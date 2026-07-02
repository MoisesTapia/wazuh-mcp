import pytest
from fastmcp import FastMCP
from unittest.mock import AsyncMock

from wazuh_mcp.api.wazuh_indexer import WazuhIndexerClient
from wazuh_mcp.tools import soc_vulnerabilities


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_vuln_hit(
    agent_name="web-01",
    agent_id="001",
    cve="CVE-2024-1234",
    severity="Critical",
    cvss=9.8,
    package="openssl",
    version="1.1.1",
):
    return {
        "_source": {
            "agent": {"id": agent_id, "name": agent_name},
            "vulnerability": {
                "id": cve,
                "severity": severity,
                "cvss": {"cvss3": {"base_score": cvss}},
                "title": f"Vulnerability in {package}",
                "published": "2024-01-01",
                "status": "VALID",
            },
            "package": {"name": package, "version": version},
        }
    }


def make_vuln_response(hits, total=None):
    return {
        "hits": {
            "total": {"value": total or len(hits)},
            "hits": hits,
        }
    }


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_indexer():
    return AsyncMock(spec=WazuhIndexerClient)


@pytest.fixture
async def fns(mock_client, mock_indexer):
    mcp = FastMCP("test")
    soc_vulnerabilities.register(mcp, mock_client, mock_indexer)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


@pytest.fixture
async def fns_no_indexer(mock_client):
    mcp = FastMCP("test")
    soc_vulnerabilities.register(mcp, mock_client, None)
    tools = await mcp.list_tools()
    result = {}
    for t in tools:
        tool = await mcp.local_provider.get_tool(t.name)
        result[t.name] = tool.fn
    return result


# ── get_vulnerabilities ───────────────────────────────────────────────────────

async def test_get_vulnerabilities_returns_cves(fns, mock_indexer):
    hit = make_vuln_hit(severity="Critical")
    mock_indexer.search.return_value = make_vuln_response([hit])
    result = await fns["get_vulnerabilities"]()
    assert result["total"] == 1
    assert len(result["vulnerabilities"]) == 1
    vuln = result["vulnerabilities"][0]
    assert "cve_id" in vuln
    assert vuln["cve_id"] == "CVE-2024-1234"


async def test_get_vulnerabilities_filter_by_agent(fns, mock_indexer):
    mock_indexer.search.return_value = make_vuln_response([])
    await fns["get_vulnerabilities"](agent_id="001")
    call_args = mock_indexer.search.call_args
    query = call_args.args[1]
    query_str = str(query)
    assert "agent.id" in query_str
    assert "001" in query_str


async def test_get_vulnerabilities_filter_by_severity(fns, mock_indexer):
    mock_indexer.search.return_value = make_vuln_response([])
    await fns["get_vulnerabilities"](severity="High")
    call_args = mock_indexer.search.call_args
    query = call_args.args[1]
    query_str = str(query)
    assert "vulnerability.severity" in query_str
    assert "High" in query_str


async def test_get_vulnerabilities_cve_uppercased(fns, mock_indexer):
    mock_indexer.search.return_value = make_vuln_response([])
    await fns["get_vulnerabilities"](cve_id="cve-2024-1234")
    call_args = mock_indexer.search.call_args
    query = call_args.args[1]
    query_str = str(query)
    assert "CVE-2024-1234" in query_str


async def test_get_vulnerabilities_no_filters_uses_match_all(fns, mock_indexer):
    mock_indexer.search.return_value = make_vuln_response([])
    await fns["get_vulnerabilities"]()
    call_args = mock_indexer.search.call_args
    query = call_args.args[1]
    assert "match_all" in query


# ── get_critical_vulnerabilities ──────────────────────────────────────────────

async def test_get_critical_vulnerabilities_filters_severity(fns, mock_indexer):
    mock_indexer.search.return_value = make_vuln_response(
        [make_vuln_hit(severity="Critical")]
    )
    await fns["get_critical_vulnerabilities"]()
    call_args = mock_indexer.search.call_args
    query = call_args.args[1]
    filter_clauses = query.get("bool", {}).get("filter", [])
    severity_terms = [
        f for f in filter_clauses
        if "term" in f and "vulnerability.severity" in f["term"]
    ]
    assert len(severity_terms) == 1
    assert severity_terms[0]["term"]["vulnerability.severity"] == "Critical"


async def test_get_critical_vulnerabilities_includes_summary_fields(fns, mock_indexer):
    hit = make_vuln_hit(agent_name="db-01", cvss=9.8)
    mock_indexer.search.return_value = make_vuln_response([hit])
    result = await fns["get_critical_vulnerabilities"]()
    assert "total" in result
    assert "avg_cvss_score" in result
    assert "agents_affected" in result


# ── get_vulnerability_summary ─────────────────────────────────────────────────

async def test_get_vulnerability_summary_parses_aggs(fns, mock_indexer):
    mock_indexer.search.return_value = {
        "hits": {"total": {"value": 15}, "hits": []},
        "aggregations": {
            "by_severity": {
                "buckets": [
                    {"key": "Critical", "doc_count": 5},
                    {"key": "High", "doc_count": 10},
                ]
            },
            "by_agent": {"buckets": []},
            "top_cves": {"buckets": []},
            "top_packages": {"buckets": []},
        },
    }
    result = await fns["get_vulnerability_summary"]()
    assert result["total_vulnerabilities"] == 15
    assert result["by_severity"]["Critical"] == 5
    assert result["by_severity"]["High"] == 10


async def test_get_vulnerability_summary_uses_size_zero(fns, mock_indexer):
    mock_indexer.search.return_value = {
        "hits": {"total": {"value": 0}, "hits": []},
        "aggregations": {
            "by_severity": {"buckets": []},
            "by_agent": {"buckets": []},
            "top_cves": {"buckets": []},
            "top_packages": {"buckets": []},
        },
    }
    await fns["get_vulnerability_summary"]()
    call_args = mock_indexer.search.call_args
    # Verify size=0
    size_arg = call_args.kwargs.get("size", call_args.args[2] if len(call_args.args) > 2 else None)
    assert size_arg == 0


# ── get_agent_risk_score ──────────────────────────────────────────────────────

async def test_get_agent_risk_score_calculates_score(fns, mock_indexer, mock_client):
    # 2 Critical CVEs, 3 High CVEs, top CVSS 9.8
    mock_indexer.search.return_value = {
        "hits": {"total": {"value": 5}, "hits": []},
        "aggregations": {
            "by_severity": {
                "buckets": [
                    {"key": "Critical", "doc_count": 2},
                    {"key": "High", "doc_count": 3},
                ]
            },
            "top_cvss": {"value": 9.8},
        },
    }

    async def mock_get(path, **kwargs):
        if "/sca/" in path:
            return {
                "data": {"affected_items": [{"score": 65}]},
                "error": 0,
            }
        if "/syscheck/" in path:
            return {
                "data": {"total_affected_items": 5, "affected_items": []},
                "error": 0,
            }
        return {}

    mock_client.get = mock_get

    result = await fns["get_agent_risk_score"](agent_id="001")
    assert 0 <= result["risk_score"] <= 100
    assert result["risk_level"] in ("Critical", "High", "Medium", "Low")
    assert result["factors"]["critical_cves"] == 2
    assert result["factors"]["high_cves"] == 3
    assert result["factors"]["top_cvss_score"] == 9.8
    assert "recommendation" in result


async def test_get_agent_risk_score_handles_sca_failure(fns, mock_indexer, mock_client):
    """Si SCA o FIM fallan, el score se calcula igual (degradación graceful)."""
    mock_indexer.search.return_value = {
        "hits": {"total": {"value": 0}, "hits": []},
        "aggregations": {
            "by_severity": {"buckets": []},
            "top_cvss": {"value": None},
        },
    }

    async def mock_get_fails(path, **kwargs):
        raise Exception("Connection refused")

    mock_client.get = mock_get_fails

    result = await fns["get_agent_risk_score"](agent_id="001")
    assert 0 <= result["risk_score"] <= 100
    assert result["factors"]["sca_score"] is None


async def test_get_agent_risk_score_no_indexer(fns_no_indexer):
    result = await fns_no_indexer["get_agent_risk_score"](agent_id="001")
    assert "error" in result or "not_configured" in result


# ── search_cve ────────────────────────────────────────────────────────────────

async def test_search_cve_finds_affected_agents(fns, mock_indexer):
    hits = [
        make_vuln_hit(agent_name="web-01", agent_id="001"),
        make_vuln_hit(agent_name="db-02", agent_id="002"),
    ]
    mock_indexer.search.return_value = make_vuln_response(hits, total=2)
    result = await fns["search_cve"](cve_id="CVE-2024-1234")
    assert result["cve_id"] == "CVE-2024-1234"
    assert result["affected_agents"] == 2
    assert len(result["details"]) == 2


async def test_search_cve_normalizes_to_uppercase(fns, mock_indexer):
    mock_indexer.search.return_value = make_vuln_response([])
    await fns["search_cve"](cve_id="cve-2024-9999")
    call_args = mock_indexer.search.call_args
    query = call_args.args[1]
    query_str = str(query)
    assert "CVE-2024-9999" in query_str


async def test_search_cve_detail_fields(fns, mock_indexer):
    hit = make_vuln_hit(
        agent_name="app-01", package="libssl", version="1.0.2", cvss=7.5
    )
    mock_indexer.search.return_value = make_vuln_response([hit])
    result = await fns["search_cve"](cve_id="CVE-2024-1234")
    detail = result["details"][0]
    assert detail["agent"] == "app-01"
    assert detail["package"] == "libssl"
    assert detail["version"] == "1.0.2"
    assert detail["cvss"] == 7.5


# ── degradación graceful ──────────────────────────────────────────────────────

async def test_all_tools_return_error_without_indexer(fns_no_indexer):
    tools_to_test = [
        ("get_vulnerabilities", {}),
        ("get_critical_vulnerabilities", {}),
        ("get_vulnerability_summary", {}),
        ("search_cve", {"cve_id": "CVE-2024-0001"}),
    ]
    for tool_name, kwargs in tools_to_test:
        result = await fns_no_indexer[tool_name](**kwargs)
        assert "error" in result or "not_configured" in result, (
            f"{tool_name} should return error dict when indexer is not configured"
        )
