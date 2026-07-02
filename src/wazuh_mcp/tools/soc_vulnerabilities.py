from __future__ import annotations

from fastmcp import FastMCP

from ..api import WazuhIndexerClient
from ..api.wazuh_indexer import VULN_INDEX
from ..client import WazuhClient

_VULN_SOURCE_FIELDS = [
    "agent.id",
    "agent.name",
    "vulnerability.id",
    "vulnerability.severity",
    "vulnerability.cvss.cvss3.base_score",
    "vulnerability.title",
    "vulnerability.published",
    "package.name",
    "package.version",
    "vulnerability.status",
]

_VULN_SORT = [
    {"vulnerability.cvss.cvss3.base_score": {"order": "desc"}},
    {"@timestamp": {"order": "desc"}},
]


def _no_indexer() -> dict:
    return {
        "error": "Wazuh Indexer no configurado",
        "not_configured": True,
        "help": "Añade WAZUH_INDEXER_HOST al .env para habilitar esta tool.",
    }


def register(
    mcp: FastMCP,
    client: WazuhClient,
    indexer: WazuhIndexerClient | None = None,
) -> None:

    @mcp.tool()
    async def get_vulnerabilities(
        agent_id: str | None = None,
        severity: str | None = None,
        cve_id: str | None = None,
        package_name: str | None = None,
        limit: int = 50,
    ) -> dict:
        """
        Busca CVEs en el Wazuh Indexer (índice wazuh-states-vulnerabilities-*).

        Requiere WAZUH_INDEXER_HOST configurado. Wazuh 4.8.0+ almacena los
        datos de vulnerabilidades exclusivamente en el Indexer.

        Args:
            agent_id:     ID del agente con zero-padding, ej. '001'.
            severity:     'Critical' | 'High' | 'Medium' | 'Low'.
            cve_id:       ID del CVE, ej. 'CVE-2024-1234'.
            package_name: Nombre del paquete afectado.
            limit:        Máximo de resultados (default 50).

        Returns:
            total y lista de vulnerabilidades ordenadas por CVSS score desc.
        """
        if indexer is None:
            return _no_indexer()

        filter_clauses: list[dict] = []
        if agent_id is not None:
            filter_clauses.append(WazuhIndexerClient.term_query("agent.id", agent_id))
        if severity is not None:
            filter_clauses.append(
                WazuhIndexerClient.term_query("vulnerability.severity", severity)
            )
        if cve_id is not None:
            filter_clauses.append(
                WazuhIndexerClient.term_query("vulnerability.id", cve_id.upper())
            )
        if package_name is not None:
            filter_clauses.append(
                WazuhIndexerClient.match_query("package.name", package_name)
            )

        if filter_clauses:
            query = WazuhIndexerClient.bool_query(filter=filter_clauses)
        else:
            query = {"match_all": {}}

        resp = await indexer.search(
            VULN_INDEX,
            query,
            size=limit,
            sort=_VULN_SORT,
            source=_VULN_SOURCE_FIELDS,
        )

        total = resp["hits"]["total"]["value"]
        vulns = [hit["_source"] for hit in resp["hits"]["hits"]]
        # Normalizar cve_id al nivel superior para acceso más fácil
        for v in vulns:
            if "vulnerability" in v and "id" in v["vulnerability"]:
                v["cve_id"] = v["vulnerability"]["id"]

        return {"total": total, "vulnerabilities": vulns}

    @mcp.tool()
    async def get_critical_vulnerabilities(
        agent_id: str | None = None,
        limit: int = 20,
    ) -> dict:
        """
        CVEs con severidad Critical ordenados por CVSS score desc.

        Identifica los riesgos más altos en toda la infraestructura o en
        un agente específico.

        Args:
            agent_id: ID del agente (None = todos los agentes).
            limit:    Máximo de resultados (default 20).

        Returns:
            total, agents_affected, avg_cvss_score, vulnerabilities.
        """
        if indexer is None:
            return _no_indexer()

        filter_clauses: list[dict] = [
            WazuhIndexerClient.term_query("vulnerability.severity", "Critical")
        ]
        if agent_id is not None:
            filter_clauses.append(WazuhIndexerClient.term_query("agent.id", agent_id))

        query = WazuhIndexerClient.bool_query(filter=filter_clauses)

        resp = await indexer.search(
            VULN_INDEX,
            query,
            size=limit,
            sort=_VULN_SORT,
            source=_VULN_SOURCE_FIELDS,
        )

        total = resp["hits"]["total"]["value"]
        hits = resp["hits"]["hits"]
        vulns = [hit["_source"] for hit in hits]
        for v in vulns:
            if "vulnerability" in v and "id" in v["vulnerability"]:
                v["cve_id"] = v["vulnerability"]["id"]

        # Post-processing
        agents_affected = sorted(
            {v.get("agent", {}).get("name", "") for v in vulns if v.get("agent")}
        )
        cvss_scores = [
            v.get("vulnerability", {}).get("cvss", {}).get("cvss3", {}).get("base_score", 0)
            for v in vulns
        ]
        avg_cvss = (
            round(sum(cvss_scores) / len(cvss_scores), 1)
            if cvss_scores
            else 0.0
        )

        return {
            "total": total,
            "agents_affected": agents_affected,
            "avg_cvss_score": avg_cvss,
            "vulnerabilities": vulns,
        }

    @mcp.tool()
    async def get_vulnerability_summary(agent_id: str | None = None) -> dict:
        """
        Resumen del estado de vulnerabilidades de toda la infraestructura.

        Args:
            agent_id: Filtra por agente específico (None = todos).

        Returns:
            total_vulnerabilities, by_severity, agents_with_critical,
            most_vulnerable_agents, top_cves, top_affected_packages.
        """
        if indexer is None:
            return _no_indexer()

        filter_clauses: list[dict] = []
        if agent_id is not None:
            filter_clauses.append(WazuhIndexerClient.term_query("agent.id", agent_id))

        if filter_clauses:
            query = WazuhIndexerClient.bool_query(filter=filter_clauses)
        else:
            query = {"match_all": {}}

        aggs = {
            "by_severity": {
                "terms": {"field": "vulnerability.severity", "size": 4}
            },
            "by_agent": {
                "terms": {"field": "agent.name.keyword", "size": 20},
                "aggs": {
                    "has_critical": {
                        "filter": {
                            "term": {"vulnerability.severity": "Critical"}
                        }
                    }
                },
            },
            "top_cves": {
                "terms": {"field": "vulnerability.id.keyword", "size": 10}
            },
            "top_packages": {
                "terms": {"field": "package.name.keyword", "size": 10}
            },
        }

        resp = await indexer.search(VULN_INDEX, query, size=0, aggs=aggs)

        total = resp["hits"]["total"]["value"]
        agg_data = resp.get("aggregations", {})

        by_severity: dict[str, int] = {}
        for b in agg_data.get("by_severity", {}).get("buckets", []):
            by_severity[b["key"]] = b["doc_count"]

        agent_buckets = agg_data.get("by_agent", {}).get("buckets", [])
        agents_with_critical = sum(
            1
            for b in agent_buckets
            if b.get("has_critical", {}).get("doc_count", 0) > 0
        )
        most_vulnerable_agents = [
            {"agent": b["key"], "count": b["doc_count"]}
            for b in agent_buckets
        ]

        top_cves = [
            {"cve": b["key"], "count": b["doc_count"]}
            for b in agg_data.get("top_cves", {}).get("buckets", [])
        ]
        top_packages = [
            {"package": b["key"], "count": b["doc_count"]}
            for b in agg_data.get("top_packages", {}).get("buckets", [])
        ]

        return {
            "total_vulnerabilities": total,
            "by_severity": by_severity,
            "agents_with_critical": agents_with_critical,
            "most_vulnerable_agents": most_vulnerable_agents,
            "top_cves": top_cves,
            "top_affected_packages": top_packages,
        }

    @mcp.tool()
    async def get_agent_risk_score(agent_id: str) -> dict:
        """
        Calcula un score de riesgo compuesto (0-100) para un agente específico.

        Combina datos del Wazuh Indexer (CVEs) con datos del Manager (SCA, FIM).

        Fórmula: score = critical_cves*20 + high_cves*5 + (100-sca_score)*0.3
                         + fim_changes_24h*2  (capped a 100)

        Args:
            agent_id: ID del agente con zero-padding, ej. '001'.

        Returns:
            agent_id, risk_score (0-100), risk_level, factors, recommendation.
        """
        if indexer is None:
            return _no_indexer()

        from datetime import datetime, timedelta, timezone

        # 1. CVEs del agente
        vuln_query = WazuhIndexerClient.bool_query(
            filter=[WazuhIndexerClient.term_query("agent.id", agent_id)]
        )
        vuln_resp = await indexer.search(
            VULN_INDEX,
            vuln_query,
            size=0,
            aggs={
                "by_severity": {"terms": {"field": "vulnerability.severity"}},
                "top_cvss": {
                    "max": {"field": "vulnerability.cvss.cvss3.base_score"}
                },
            },
        )

        severity_counts: dict[str, int] = {
            b["key"]: b["doc_count"]
            for b in vuln_resp.get("aggregations", {})
            .get("by_severity", {})
            .get("buckets", [])
        }
        critical_cves = severity_counts.get("Critical", 0)
        high_cves = severity_counts.get("High", 0)
        top_cvss = float(
            vuln_resp.get("aggregations", {}).get("top_cvss", {}).get("value") or 0.0
        )

        # 2. SCA score del Manager
        sca_score: float | None = None
        try:
            sca_resp = await client.get(f"/sca/{agent_id}")
            items = sca_resp.get("data", {}).get("affected_items", [])
            if items:
                sca_score = float(items[0].get("score", 0))
        except Exception:
            pass

        # 3. Cambios FIM en las últimas 24h
        fim_changes_24h = 0
        try:
            newer_than = (
                datetime.now(timezone.utc) - timedelta(hours=24)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            fim_resp = await client.get(
                f"/syscheck/{agent_id}",
                params={"newer_than": newer_than, "limit": 1},
            )
            fim_changes_24h = int(
                fim_resp.get("data", {}).get("total_affected_items", 0)
            )
        except Exception:
            pass

        # Fórmula de riesgo
        sca_contribution = (100 - sca_score) * 0.3 if sca_score is not None else 30.0
        raw_score = (
            critical_cves * 20
            + high_cves * 5
            + sca_contribution
            + fim_changes_24h * 2
        )
        risk_score = min(100, int(raw_score))

        if risk_score >= 80:
            risk_level = "Critical"
        elif risk_score >= 60:
            risk_level = "High"
        elif risk_score >= 40:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        # Recomendaciones priorizadas
        rec_parts: list[str] = []
        if critical_cves > 0:
            rec_parts.append(f"Parchear {critical_cves} CVE(s) crítico(s) inmediatamente")
        if high_cves > 0:
            rec_parts.append(f"Revisar {high_cves} CVE(s) de severidad alta")
        if sca_score is not None and sca_score < 70:
            rec_parts.append(
                f"Mejorar configuración de seguridad (SCA score: {sca_score:.0f}%)"
            )
        if fim_changes_24h > 5:
            rec_parts.append(
                f"Investigar {fim_changes_24h} cambios de archivos en las últimas 24h"
            )

        recommendation = (
            ". ".join(rec_parts[:3]) + "."
            if rec_parts
            else "El agente presenta un perfil de riesgo aceptable. Mantener monitoreo regular."
        )

        return {
            "agent_id": agent_id,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "factors": {
                "critical_cves": critical_cves,
                "high_cves": high_cves,
                "sca_score": sca_score,
                "fim_changes_24h": fim_changes_24h,
                "top_cvss_score": top_cvss,
            },
            "recommendation": recommendation,
        }

    @mcp.tool()
    async def search_cve(cve_id: str) -> dict:
        """
        Busca un CVE específico en todos los agentes monitoreados.

        Args:
            cve_id: Identificador del CVE, ej. 'CVE-2024-1234'.

        Returns:
            cve_id, affected_agents (count), details por agente.
        """
        if indexer is None:
            return _no_indexer()

        normalized = cve_id.upper()
        query = WazuhIndexerClient.bool_query(
            filter=[WazuhIndexerClient.term_query("vulnerability.id", normalized)]
        )

        resp = await indexer.search(
            VULN_INDEX,
            query,
            size=100,
            source=[
                "agent.name",
                "package.name",
                "package.version",
                "vulnerability.severity",
                "vulnerability.cvss.cvss3.base_score",
            ],
        )

        total = resp["hits"]["total"]["value"]
        details = [
            {
                "agent": hit["_source"].get("agent", {}).get("name", ""),
                "package": hit["_source"].get("package", {}).get("name", ""),
                "version": hit["_source"].get("package", {}).get("version", ""),
                "severity": hit["_source"]
                .get("vulnerability", {})
                .get("severity", ""),
                "cvss": hit["_source"]
                .get("vulnerability", {})
                .get("cvss", {})
                .get("cvss3", {})
                .get("base_score", 0),
            }
            for hit in resp["hits"]["hits"]
        ]

        return {
            "cve_id": normalized,
            "affected_agents": total,
            "details": details,
        }
