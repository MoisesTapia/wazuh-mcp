from __future__ import annotations

from fastmcp import FastMCP

from ..api import WazuhIndexerClient
from ..api.wazuh_indexer import ALERT_INDEX
from ..client import WazuhClient

_SOURCE_FIELDS = [
    "@timestamp",
    "agent.id",
    "agent.name",
    "rule.id",
    "rule.level",
    "rule.description",
    "rule.groups",
    "rule.mitre.id",
    "rule.mitre.tactic",
    "data.srcip",
    "data.dstip",
    "data.srcuser",
    "location",
]

_DEFAULT_SORT = [{"@timestamp": {"order": "desc"}}]


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
    async def get_alerts(
        hours: int = 24,
        level: int | None = None,
        agent_id: str | None = None,
        rule_id: str | None = None,
        group: str | None = None,
        limit: int = 50,
    ) -> dict:
        """
        Busca alertas en el Wazuh Indexer (puerto 9200).

        Requiere WAZUH_INDEXER_HOST configurado. Filtra por ventana de tiempo
        y opcionalmente por nivel de severidad, agente, regla o grupo.

        Args:
            hours:    Ventana de tiempo en horas hacia atrás (default 24).
            level:    Nivel mínimo de alerta Wazuh (0-15). Ej: 10 para crítico.
            agent_id: ID del agente con zero-padding, ej. '001'.
            rule_id:  ID de regla Wazuh, ej. '5712'.
            group:    Grupo de regla, ej. 'authentication_failed'.
            limit:    Máximo de alertas a devolver (default 50).

        Returns:
            total, alerts (lista de documentos del Indexer), query_hours.
        """
        if indexer is None:
            return _no_indexer()

        filter_clauses: list[dict] = [WazuhIndexerClient.time_range_query(hours)]
        if level is not None:
            filter_clauses.append({"range": {"rule.level": {"gte": level}}})
        if agent_id is not None:
            filter_clauses.append(WazuhIndexerClient.term_query("agent.id", agent_id))
        if rule_id is not None:
            filter_clauses.append(WazuhIndexerClient.term_query("rule.id", rule_id))
        if group is not None:
            filter_clauses.append(WazuhIndexerClient.match_query("rule.groups", group))

        query = WazuhIndexerClient.bool_query(filter=filter_clauses)

        resp = await indexer.search(
            ALERT_INDEX,
            query,
            size=limit,
            sort=_DEFAULT_SORT,
            source=_SOURCE_FIELDS,
        )

        total = resp["hits"]["total"]["value"]
        hits = resp["hits"]["hits"]
        alerts = [indexer.redact_alert(hit)["_source"] for hit in hits]

        return {"total": total, "alerts": alerts, "query_hours": hours}

    @mcp.tool()
    async def get_critical_alerts(hours: int = 24, limit: int = 20) -> dict:
        """
        Devuelve las alertas de nivel crítico (>=12) más recientes.

        Level 12+ = crítico en Wazuh (escala 0-15).

        Args:
            hours: Ventana de tiempo en horas (default 24).
            limit: Máximo de alertas a devolver (default 20).

        Returns:
            total, alerts ordenadas por timestamp desc, query_hours.
        """
        if indexer is None:
            return _no_indexer()

        filter_clauses: list[dict] = [
            WazuhIndexerClient.time_range_query(hours),
            {"range": {"rule.level": {"gte": 12}}},
        ]
        query = WazuhIndexerClient.bool_query(filter=filter_clauses)

        resp = await indexer.search(
            ALERT_INDEX,
            query,
            size=limit,
            sort=_DEFAULT_SORT,
            source=_SOURCE_FIELDS,
        )

        total = resp["hits"]["total"]["value"]
        hits = resp["hits"]["hits"]
        alerts = [indexer.redact_alert(hit)["_source"] for hit in hits]

        return {
            "total": total,
            "alerts": alerts,
            "query_hours": hours,
            "level_filter": "critical (>=12)",
        }

    @mcp.tool()
    async def get_alert_summary(hours: int = 24) -> dict:
        """
        Resumen estadístico de alertas: distribución por nivel, top agentes,
        top reglas, top grupos y tácticas MITRE ATT&CK.

        Args:
            hours: Ventana de tiempo en horas (default 24).

        Returns:
            period_hours, total_alerts, by_level, top_agents, top_rules,
            top_groups, mitre_tactics.
        """
        if indexer is None:
            return _no_indexer()

        query = WazuhIndexerClient.bool_query(
            filter=[WazuhIndexerClient.time_range_query(hours)]
        )
        aggs = {
            "levels_dist": {"terms": {"field": "rule.level", "size": 16}},
            "top_agents": {"terms": {"field": "agent.name.keyword", "size": 10}},
            "top_rules": {"terms": {"field": "rule.id.keyword", "size": 10}},
            "top_groups": {"terms": {"field": "rule.groups.keyword", "size": 10}},
            "mitre_tactics": {
                "terms": {"field": "rule.mitre.tactic.keyword", "size": 15}
            },
        }

        resp = await indexer.search(ALERT_INDEX, query, size=0, aggs=aggs)

        total = resp["hits"]["total"]["value"]
        agg_data = resp.get("aggregations", {})

        by_level = {
            str(b["key"]): b["doc_count"]
            for b in agg_data.get("levels_dist", {}).get("buckets", [])
        }
        top_agents = [
            {"agent": b["key"], "count": b["doc_count"]}
            for b in agg_data.get("top_agents", {}).get("buckets", [])
        ]
        top_rules = [
            {"rule_id": b["key"], "count": b["doc_count"]}
            for b in agg_data.get("top_rules", {}).get("buckets", [])
        ]
        top_groups = [
            {"group": b["key"], "count": b["doc_count"]}
            for b in agg_data.get("top_groups", {}).get("buckets", [])
        ]
        mitre_tactics = [
            {"tactic": b["key"], "count": b["doc_count"]}
            for b in agg_data.get("mitre_tactics", {}).get("buckets", [])
        ]

        return {
            "period_hours": hours,
            "total_alerts": total,
            "by_level": by_level,
            "top_agents": top_agents,
            "top_rules": top_rules,
            "top_groups": top_groups,
            "mitre_tactics": mitre_tactics,
        }

    @mcp.tool()
    async def search_alerts(
        query_string: str,
        hours: int = 24,
        limit: int = 30,
    ) -> dict:
        """
        Búsqueda de texto libre en alertas usando Elasticsearch query_string.

        Permite consultas tipo: 'ssh AND brute' o 'rule.level:>=10'.
        Útil para threat hunting: buscar IOCs, IPs, usuarios, comandos.

        Args:
            query_string: Expresión de búsqueda ES (ej: 'sshd AND failed').
            hours:        Ventana de tiempo en horas (default 24).
            limit:        Máximo de resultados (default 30).

        Returns:
            total, alerts redactadas, query_string original, query_hours.
        """
        if indexer is None:
            return _no_indexer()

        query = WazuhIndexerClient.bool_query(
            must=[{"query_string": {"query": query_string}}],
            filter=[WazuhIndexerClient.time_range_query(hours)],
        )

        resp = await indexer.search(
            ALERT_INDEX,
            query,
            size=limit,
            sort=_DEFAULT_SORT,
        )

        total = resp["hits"]["total"]["value"]
        hits = resp["hits"]["hits"]
        alerts = [indexer.redact_alert(hit)["_source"] for hit in hits]

        return {
            "total": total,
            "alerts": alerts,
            "query_string": query_string,
            "query_hours": hours,
        }

    @mcp.tool()
    async def get_agent_alert_timeline(
        agent_id: str,
        hours: int = 24,
        interval: str = "1h",
    ) -> dict:
        """
        Línea de tiempo de alertas de un agente específico.

        Args:
            agent_id: ID del agente con zero-padding, ej. '001'.
            hours:    Ventana de tiempo en horas (default 24).
            interval: Intervalo del histograma (1h, 30m, 1d, etc.).

        Returns:
            agent_id, period_hours, interval, total, timeline con
            timestamp/count/max_level por bucket.
        """
        if indexer is None:
            return _no_indexer()

        query = WazuhIndexerClient.bool_query(
            filter=[
                WazuhIndexerClient.time_range_query(hours),
                WazuhIndexerClient.term_query("agent.id", agent_id),
            ]
        )
        aggs = {
            "timeline": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": interval,
                },
                "aggs": {
                    "max_level": {"max": {"field": "rule.level"}}
                },
            }
        }

        resp = await indexer.search(ALERT_INDEX, query, size=0, aggs=aggs)

        total = resp["hits"]["total"]["value"]
        buckets = (
            resp.get("aggregations", {}).get("timeline", {}).get("buckets", [])
        )
        timeline = [
            {
                "timestamp": b.get("key_as_string", ""),
                "count": b["doc_count"],
                "max_level": int(b.get("max_level", {}).get("value") or 0),
            }
            for b in buckets
        ]

        return {
            "agent_id": agent_id,
            "period_hours": hours,
            "interval": interval,
            "timeline": timeline,
            "total": total,
        }

    @mcp.tool()
    async def get_top_threats(hours: int = 24, limit: int = 10) -> list:
        """
        Top amenazas por score combinado (frecuencia × severidad máxima).

        Útil para priorizar qué reglas requieren atención inmediata.

        Args:
            hours: Ventana de tiempo en horas (default 24).
            limit: Número de amenazas a devolver (default 10).

        Returns:
            Lista ordenada por score desc con rule_id, description,
            count, max_level y score.
        """
        if indexer is None:
            return [_no_indexer()]

        query = WazuhIndexerClient.bool_query(
            filter=[WazuhIndexerClient.time_range_query(hours)]
        )
        aggs = {
            "top_rules": {
                "terms": {"field": "rule.id.keyword", "size": 50},
                "aggs": {
                    "max_level": {"max": {"field": "rule.level"}},
                    "sample_desc": {
                        "terms": {"field": "rule.description.keyword", "size": 1}
                    },
                },
            }
        }

        resp = await indexer.search(ALERT_INDEX, query, size=0, aggs=aggs)

        threats = []
        for bucket in (
            resp.get("aggregations", {}).get("top_rules", {}).get("buckets", [])
        ):
            rule_id = bucket["key"]
            count = bucket["doc_count"]
            max_level = int(bucket.get("max_level", {}).get("value") or 0)
            desc_buckets = bucket.get("sample_desc", {}).get("buckets", [])
            description = desc_buckets[0]["key"] if desc_buckets else ""
            score = count * max_level
            threats.append(
                {
                    "rule_id": rule_id,
                    "description": description,
                    "count": count,
                    "max_level": max_level,
                    "score": score,
                }
            )

        threats.sort(key=lambda x: x["score"], reverse=True)
        return threats[:limit]

    @mcp.tool()
    async def analyze_alert_patterns(
        agent_id: str | None = None,
        hours: int = 24,
    ) -> dict:
        """
        Análisis de patrones de alertas para detectar comportamiento anómalo.

        Calcula distribución horaria, top IPs de origen, top puertos de destino,
        hora pico y ratio de alertas fuera de horario laboral (22h-6h).

        Args:
            agent_id: ID del agente (None = todos los agentes).
            hours:    Ventana de tiempo en horas (default 24).

        Returns:
            agent_id, period_hours, peak_hour, off_hours_ratio,
            hourly_distribution, top_source_ips, suspicious_ips, top_dest_ports.
        """
        if indexer is None:
            return _no_indexer()

        from datetime import datetime

        filter_clauses: list[dict] = [WazuhIndexerClient.time_range_query(hours)]
        if agent_id is not None:
            filter_clauses.append(WazuhIndexerClient.term_query("agent.id", agent_id))

        query = WazuhIndexerClient.bool_query(filter=filter_clauses)
        aggs = {
            "hourly_dist": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": "1h",
                }
            },
            "top_source_ips": {
                "terms": {"field": "data.srcip.keyword", "size": 20}
            },
            "top_dest_ports": {
                "terms": {"field": "data.dstport", "size": 10}
            },
        }

        resp = await indexer.search(ALERT_INDEX, query, size=0, aggs=aggs)

        total = resp["hits"]["total"]["value"]
        agg_data = resp.get("aggregations", {})

        # Hourly distribution + peak + off-hours ratio
        hourly_buckets = agg_data.get("hourly_dist", {}).get("buckets", [])
        peak_hour = 0
        peak_count = 0
        off_hours_count = 0
        hourly_distribution = []
        for b in hourly_buckets:
            ts = b.get("key_as_string", "")
            count = b["doc_count"]
            hourly_distribution.append({"timestamp": ts, "count": count})
            if count > peak_count:
                peak_count = count
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    peak_hour = dt.hour
                except Exception:
                    pass
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt.hour >= 22 or dt.hour < 6:
                    off_hours_count += count
            except Exception:
                pass

        off_hours_ratio = round(off_hours_count / total, 2) if total > 0 else 0.0

        # Source IPs
        top_ips = [
            {"ip": b["key"], "count": b["doc_count"]}
            for b in agg_data.get("top_source_ips", {}).get("buckets", [])
        ]
        suspicious_ips = [ip for ip in top_ips if ip["count"] > 10]

        # Dest ports
        top_ports = [
            {"port": b["key"], "count": b["doc_count"]}
            for b in agg_data.get("top_dest_ports", {}).get("buckets", [])
        ]

        return {
            "agent_id": agent_id or "all",
            "period_hours": hours,
            "peak_hour": peak_hour,
            "off_hours_ratio": off_hours_ratio,
            "hourly_distribution": hourly_distribution,
            "top_source_ips": top_ips,
            "suspicious_ips": suspicious_ips,
            "top_dest_ports": top_ports,
        }
