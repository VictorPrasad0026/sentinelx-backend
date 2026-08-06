"""
SentinelX Attack Surface Mapper

Produces a structured attack surface view from the graph.
Maps every internet-facing asset and its exposure chain.
"""

from intelligence_engine.graph.graph_queries import GraphQuery
from intelligence_engine.intelligence.asset_criticality import score_asset
from intelligence_engine.intelligence.exposure_analyzer import analyze_exposure


def map_attack_surface(graph: dict, profile: dict) -> dict:
    gq = GraphQuery(graph)

    assets = []

    # All subdomains + domain itself
    targets = (
        gq.by_type("Subdomain") +
        gq.by_type("Domain")
    )

    for node in targets:
        host = node["name"]
        props = node.get("properties", {})

        open_ports = [
            n["properties"]["port"]
            for n in gq.neighbors(node["node_id"], "HAS_PORT")
            if n.get("properties", {}).get("port")
        ]

        technologies = [
            n["name"]
            for n in gq.neighbors(node["node_id"], "USES")
            if n["node_type"] == "Technology"
        ] + [
            n["name"]
            for n in gq.neighbors(node["node_id"], "SHARES_TECHNOLOGY")
            if n["node_type"] == "Technology"
        ]

        findings = gq.neighbors(node["node_id"], "HAS_FINDING")
        risk_severity = props.get("risk_severity", "UNKNOWN")
        risk_score    = props.get("risk_score", 0)

        criticality = score_asset(
            host, open_ports, technologies,
            risk_severity, len(findings)
        )

        # Pull WAF / CDN / SSL from graph
        waf_detected = bool(gq.neighbors(node["node_id"], "PROTECTED_BY"))
        cdn_detected = any(
            n["node_type"] == "CDN"
            for n in gq.neighbors(node["node_id"], "PROTECTED_BY")
        )
        cert_nodes = gq.neighbors(node["node_id"], "HAS_CERTIFICATE")
        ssl_status = (cert_nodes[0].get("properties", {}).get("status", "UNKNOWN")
                      if cert_nodes else "UNKNOWN")

        exposure = analyze_exposure(
            host, open_ports, waf_detected, cdn_detected, ssl_status
        )

        assets.append({
            "host":              host,
            "node_type":         node["node_type"],
            "criticality":       criticality,
            "exposure":          exposure,
            "open_ports":        open_ports,
            "technologies":      list(set(technologies)),
            "finding_count":     len(findings),
            "risk_score":        risk_score,
            "risk_severity":     risk_severity,
        })

    assets.sort(key=lambda x: x["criticality"]["criticality_score"], reverse=True)

    crown_jewels = [a for a in assets if a["criticality"]["is_crown_jewel"]]
    internet_facing = [a for a in assets if a["exposure"]["direct_internet"]]

    return {
        "total_assets":       len(assets),
        "crown_jewels":       crown_jewels,
        "internet_facing":    internet_facing,
        "assets":             assets,
        "surface_summary": {
            "crown_jewel_count":    len(crown_jewels),
            "internet_facing_count": len(internet_facing),
            "critical_exposure":    [a["host"] for a in assets
                                     if a["exposure"]["exposure_level"] == "CRITICAL"],
        },
    }
