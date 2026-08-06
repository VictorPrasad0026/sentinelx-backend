"""
SentinelX Internet Exposure Analyzer

Produces a complete internet exposure inventory:
every asset that is directly reachable from the internet,
with what services and what protection it has.

Separate from asset_criticality — this is purely about reachability.
"""

from intelligence_engine.graph.graph_queries import GraphQuery

DANGEROUS_INTERNET_PORTS = {
    23: "TELNET — cleartext remote access",
    3306: "MySQL — database directly exposed",
    5432: "PostgreSQL — database directly exposed",
    6379: "Redis — no-auth cache exposed",
    27017: "MongoDB — no-auth database exposed",
    9200: "Elasticsearch — no-auth search engine exposed",
    2375: "Docker API — container engine exposed",
    10250: "Kubernetes API — cluster exposed",
    445: "SMB — Windows file sharing exposed",
    3389: "RDP — remote desktop exposed",
    4444: "Metasploit default — likely compromised",
    31337: "Back Orifice/backdoor port",
}


def build_exposure_inventory(graph: dict, profile: dict) -> dict:
    gq = GraphQuery(graph)

    exposed_assets = []
    dangerous_exposures = []

    all_assets = gq.by_type("Domain") + gq.by_type("Subdomain")

    for asset_node in all_assets:
        host = asset_node["name"]
        port_nodes = gq.neighbors(asset_node["node_id"], "HAS_PORT")

        if not port_nodes:
            continue

        open_ports = []
        for pn in port_nodes:
            props = pn["properties"]
            port_num = props.get("port")
            svc      = props.get("service", "UNKNOWN")
            risk     = props.get("risk", "LOW")
            banner   = props.get("banner")
            open_ports.append({
                "port":    port_num,
                "service": svc,
                "risk":    risk,
                "banner":  banner,
            })

            if port_num in DANGEROUS_INTERNET_PORTS:
                dangerous_exposures.append({
                    "host":        host,
                    "port":        port_num,
                    "service":     svc,
                    "description": DANGEROUS_INTERNET_PORTS[port_num],
                    "risk":        "CRITICAL",
                })

        # Protection info
        protected_by = gq.neighbors(asset_node["node_id"], "PROTECTED_BY")
        waf = any(n["node_type"] == "WAF" for n in protected_by)
        cdn = any(n["node_type"] == "CDN" for n in protected_by)

        exposed_assets.append({
            "host":       host,
            "open_ports": open_ports,
            "port_count": len(open_ports),
            "waf":        waf,
            "cdn":        cdn,
            "protected":  waf or cdn,
        })

    exposed_assets.sort(key=lambda x: x["port_count"], reverse=True)

    return {
        "total_exposed_assets":     len(exposed_assets),
        "dangerous_exposures":      dangerous_exposures,
        "dangerous_exposure_count": len(dangerous_exposures),
        "unprotected_assets":       [a for a in exposed_assets if not a["protected"]],
        "all_exposed_assets":       exposed_assets,
        "summary": (
            f"{len(exposed_assets)} internet-facing assets with open ports. "
            f"{len(dangerous_exposures)} dangerous exposures detected."
        ),
    }
