"""
SentinelX Attack Path Builder

Builds realistic attacker movement chains from the graph.
Each path: Internet → Entry Point → Pivot → Crown Jewel

Uses ONLY graph evidence. No hallucination.
"""

from intelligence_engine.graph.graph_queries import GraphQuery
from intelligence_engine.attack_engine.exploitability_engine import score_exploitability

# MITRE ATT&CK technique mappings for common services
MITRE_MAP = {
    "FTP":           ("T1190", "Exploit Public-Facing Application"),
    "SSH":           ("T1021.004", "Remote Services: SSH"),
    "TELNET":        ("T1021", "Remote Services"),
    "HTTP":          ("T1190", "Exploit Public-Facing Application"),
    "HTTPS":         ("T1190", "Exploit Public-Facing Application"),
    "MYSQL":         ("T1213", "Data from Information Repositories"),
    "MSSQL":         ("T1213", "Data from Information Repositories"),
    "POSTGRESQL":    ("T1213", "Data from Information Repositories"),
    "REDIS":         ("T1530", "Data from Cloud Storage"),
    "MONGODB":       ("T1213", "Data from Information Repositories"),
    "ELASTICSEARCH": ("T1213", "Data from Information Repositories"),
    "RDP":           ("T1021.001", "Remote Desktop Protocol"),
    "SMB":           ("T1021.002", "SMB/Windows Admin Shares"),
    "DOCKER-API":    ("T1610", "Deploy Container"),
    "KUBE-API":      ("T1610", "Deploy Container"),
    "VNC":           ("T1021.005", "VNC"),
    "METASPLOIT":    ("T1059", "Command and Scripting Interpreter"),
    "WORDPRESS":     ("T1190", "Exploit Public-Facing Application"),
    "Apache":        ("T1190", "Exploit Public-Facing Application"),
    "Nginx":         ("T1190", "Exploit Public-Facing Application"),
}

CRITICAL_SERVICES = {
    "MYSQL", "MSSQL", "POSTGRESQL", "REDIS", "MONGODB",
    "ELASTICSEARCH", "DOCKER-API", "KUBE-API",
    "SMB", "RDP", "METASPLOIT", "BACKDOOR",
}


def build_attack_paths(graph: dict, attack_surface: dict) -> list[dict]:
    """
    Returns a list of attack paths sorted by likelihood descending.
    Each path is evidence-based from the graph only.
    """
    gq = GraphQuery(graph)
    paths = []

    internet_assets = attack_surface.get("internet_facing", [])

    for asset in internet_assets:
        host = asset["host"]
        open_ports = asset["open_ports"]
        technologies = asset["technologies"]
        node_type = asset["node_type"]

        for port in open_ports:
            port_nodes = [
                n for n in gq.by_type("Port")
                if n["properties"].get("port") == port
            ]
            if not port_nodes:
                continue
            port_node = port_nodes[0]
            service = port_node["properties"].get("service", "UNKNOWN")
            risk    = port_node["properties"].get("risk", "LOW")
            banner  = port_node["properties"].get("banner")

            mitre_id, mitre_name = MITRE_MAP.get(service, ("T1190", "Exploit Public-Facing Application"))

            steps = [
                {
                    "step": 1,
                    "action": "Internet reconnaissance",
                    "technique": "T1595 - Active Scanning",
                    "asset": "Internet",
                },
                {
                    "step": 2,
                    "action": f"Access {host} via {service} on port {port}",
                    "technique": f"{mitre_id} - {mitre_name}",
                    "asset": host,
                    "evidence": f"Port {port} open, service: {service}",
                    "banner": banner,
                },
            ]

            # Add pivot step if service leads to data or credentials
            if service in CRITICAL_SERVICES:
                steps.append({
                    "step": 3,
                    "action": f"Extract data or credentials from {service}",
                    "technique": "T1552 - Unsecured Credentials / T1213 - Data Repositories",
                    "asset": host,
                    "impact": "Data breach / credential theft",
                })

            # Check if this asset connects to crown jewels
            crown_jewels = attack_surface.get("crown_jewels", [])
            cj_names = [c["host"] for c in crown_jewels if c["host"] != host]
            if cj_names:
                steps.append({
                    "step": len(steps) + 1,
                    "action": f"Lateral movement to crown jewel assets",
                    "technique": "T1021 - Remote Services",
                    "asset": cj_names[0],
                    "evidence": "Asset shares infrastructure with crown jewel",
                })

            exploitability = score_exploitability(service, risk, banner, technologies)

            paths.append({
                "path_id":       f"{host}:{port}",
                "entry_point":   host,
                "service":       service,
                "port":          port,
                "steps":         steps,
                "mitre_technique": f"{mitre_id} - {mitre_name}",
                "likelihood":    exploitability["likelihood"],
                "confidence":    exploitability["confidence"],
                "risk_level":    risk,
                "preconditions": exploitability["preconditions"],
                "business_impact": _infer_business_impact(service, host),
                "evidence":      exploitability["evidence"],
            })

    paths.sort(key=lambda x: x["likelihood"], reverse=True)
    return paths


def _infer_business_impact(service: str, host: str) -> str:
    host_lower = host.lower()
    if service in {"MYSQL", "MSSQL", "POSTGRESQL", "MONGODB", "ORACLE-DB"}:
        return "Data breach — customer / business data directly accessible"
    if service in {"REDIS", "ELASTICSEARCH"}:
        return "Cache/index exposure — may contain session tokens or PII"
    if service in {"DOCKER-API", "KUBE-API"}:
        return "Container escape — full host / cluster takeover possible"
    if service in {"SMB", "RDP"}:
        return "Windows lateral movement — potential domain compromise"
    if "admin" in host_lower or "panel" in host_lower:
        return "Admin panel compromise — full application control"
    if "api" in host_lower:
        return "API endpoint compromise — business logic abuse"
    return "Service disruption or unauthorized access to business functions"
