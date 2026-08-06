"""
SentinelX Lateral Movement Engine

Models how an attacker moves from an initial foothold
to adjacent systems using discovered services and relationships.

Detects pivot opportunities from:
  - Shared IPs (one compromise → same-IP assets reachable)
  - Shared certificates (same server → same host likely)
  - Internal service exposure (LDAP, SMB, RDP, Kerberos)
  - Container networks (Docker API → internal services)
"""

from intelligence_engine.graph.graph_queries import GraphQuery

PIVOT_SERVICES = {
    "SMB":           {"technique": "T1021.002", "name": "SMB/Windows Admin Shares", "risk": "CRITICAL"},
    "RDP":           {"technique": "T1021.001", "name": "Remote Desktop Protocol",  "risk": "HIGH"},
    "WINRM-HTTP":    {"technique": "T1021.006", "name": "Windows Remote Management","risk": "HIGH"},
    "WINRM-HTTPS":   {"technique": "T1021.006", "name": "Windows Remote Management","risk": "HIGH"},
    "SSH":           {"technique": "T1021.004", "name": "SSH Remote Services",      "risk": "MEDIUM"},
    "LDAP":          {"technique": "T1087.002", "name": "Domain Account Discovery", "risk": "HIGH"},
    "LDAPS":         {"technique": "T1087.002", "name": "Domain Account Discovery", "risk": "HIGH"},
    "KERBEROS":      {"technique": "T1558",     "name": "Kerberoasting",            "risk": "CRITICAL"},
    "DOCKER-API":    {"technique": "T1610",     "name": "Deploy Container",         "risk": "CRITICAL"},
    "DOCKER-TLS":    {"technique": "T1610",     "name": "Deploy Container",         "risk": "HIGH"},
}


def discover_lateral_paths(graph: dict, initial_host: str) -> list:
    """
    Given an initial compromised host, find all lateral movement paths.
    Returns list of pivot opportunities.
    """
    gq = GraphQuery(graph)
    pivots = []

    # Find the initial host node
    all_nodes = gq.by_type("Subdomain") + gq.by_type("Domain")
    initial_node = next((n for n in all_nodes if n["name"] == initial_host), None)
    if not initial_node:
        return []

    # ── SHARES_IP pivot ────────────────────────────────────────
    shared_ip_edges = [
        e for e in graph["edges"]
        if e["rel_type"] == "SHARES_IP"
        and (e["source_id"] == initial_node["node_id"]
             or e["target_id"] == initial_node["node_id"])
    ]
    for e in shared_ip_edges:
        peer_id = e["target_id"] if e["source_id"] == initial_node["node_id"] else e["source_id"]
        peer = gq.nodes.get(peer_id)
        if peer and peer["name"] != initial_host:
            pivots.append({
                "type":       "SHARES_IP",
                "from":       initial_host,
                "to":         peer["name"],
                "technique":  "T1021",
                "description": f"Both assets share the same IP — compromise of {initial_host} provides network adjacency to {peer['name']}",
                "confidence": "HIGH",
            })

    # ── SHARES_CERTIFICATE pivot ───────────────────────────────
    shared_cert_edges = [
        e for e in graph["edges"]
        if e["rel_type"] == "SHARES_CERTIFICATE"
        and (e["source_id"] == initial_node["node_id"]
             or e["target_id"] == initial_node["node_id"])
    ]
    for e in shared_cert_edges:
        peer_id = e["target_id"] if e["source_id"] == initial_node["node_id"] else e["source_id"]
        peer = gq.nodes.get(peer_id)
        if peer and peer["name"] != initial_host:
            pivots.append({
                "type":       "SHARES_CERTIFICATE",
                "from":       initial_host,
                "to":         peer["name"],
                "technique":  "T1021",
                "description": f"Shared TLS certificate suggests co-hosting — attacker may reach {peer['name']} from same server",
                "confidence": "MEDIUM",
            })

    # ── Internal service pivot ─────────────────────────────────
    port_nodes = gq.neighbors(initial_node["node_id"], "HAS_PORT")
    for port_node in port_nodes:
        service = port_node["properties"].get("service", "")
        pivot_info = PIVOT_SERVICES.get(service)
        if pivot_info:
            pivots.append({
                "type":       "SERVICE_PIVOT",
                "from":       "Internet",
                "to":         initial_host,
                "service":    service,
                "port":       port_node["properties"].get("port"),
                "technique":  pivot_info["technique"],
                "description": f"{service} exposed on {initial_host} enables {pivot_info['name']}",
                "confidence": "HIGH",
                "risk":       pivot_info["risk"],
            })

    return pivots


def find_all_lateral_paths(graph: dict, compromised_hosts: list) -> dict:
    all_pivots = []
    for host in compromised_hosts:
        all_pivots.extend(discover_lateral_paths(graph, host))

    return {
        "total_pivot_opportunities": len(all_pivots),
        "pivots": all_pivots,
        "high_risk_pivots": [p for p in all_pivots if p.get("risk") in ("CRITICAL", "HIGH")],
    }
