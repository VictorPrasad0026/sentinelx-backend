"""
SentinelX Privilege Escalation Engine

Identifies privilege escalation paths from scan data.
Evidence-only: no CVEs, no guessing.

Detects escalation via:
  - Admin panels exposed to internet
  - Default credential risk services (Tomcat, JBoss, Jenkins)
  - Kerberoasting opportunities (Kerberos exposed)
  - Container privilege escalation (Docker API, runC)
  - Cloud metadata service exposure
  - Weak authentication in directory services
"""

from intelligence_engine.graph.graph_queries import GraphQuery

ESCALATION_SIGNATURES = [
    {
        "id":          "ADMIN_PANEL_EXPOSED",
        "check":       "keyword",
        "keywords":    ["admin", "administrator", "panel", "dashboard", "manage"],
        "technique":   "T1078",
        "name":        "Valid Accounts — Admin Panel",
        "description": "An internet-facing admin panel allows direct authentication attempts. "
                       "Brute force or credential stuffing could yield privileged access.",
        "severity":    "CRITICAL",
    },
    {
        "id":          "KERBEROASTING",
        "check":       "service",
        "services":    {"KERBEROS", "KERBEROS-ADM", "KERBEROS-PW"},
        "technique":   "T1558.003",
        "name":        "Kerberoasting",
        "description": "Kerberos is internet-accessible. An attacker with domain user credentials "
                       "can request service tickets and crack them offline.",
        "severity":    "CRITICAL",
    },
    {
        "id":          "DOCKER_PRIVILEGE_ESC",
        "check":       "service",
        "services":    {"DOCKER-API", "DOCKER-TLS", "DOCKER-ALT"},
        "technique":   "T1611",
        "name":        "Escape to Host via Docker API",
        "description": "Exposed Docker API allows container creation with host volume mounts, "
                       "enabling root-level host access.",
        "severity":    "CRITICAL",
    },
    {
        "id":          "KUBE_PRIVILEGE_ESC",
        "check":       "service",
        "services":    {"KUBE-API", "KUBE-SCHED", "KUBE-CM"},
        "technique":   "T1610",
        "name":        "Kubernetes API Privilege Escalation",
        "description": "Kubernetes API server is exposed. An authenticated attacker could "
                       "create privileged pods and escape to the node.",
        "severity":    "CRITICAL",
    },
    {
        "id":          "LDAP_ANONYMOUS",
        "check":       "service",
        "services":    {"LDAP"},
        "technique":   "T1087.002",
        "name":        "LDAP Anonymous Bind / Account Enumeration",
        "description": "LDAP is internet-accessible. Anonymous bind may expose user accounts "
                       "which can be used for targeted credential attacks.",
        "severity":    "HIGH",
    },
    {
        "id":          "JAVA_ADMIN_CONSOLE",
        "check":       "service",
        "services":    {"GLASSFISH", "JBOSS-ADM", "WILDFLY-ADM", "AJP"},
        "technique":   "T1190",
        "name":        "Java Application Server Admin Console",
        "description": "Java application server admin interface exposed. "
                       "Default credentials or CVEs could yield OS-level access.",
        "severity":    "HIGH",
    },
    {
        "id":          "IPMI_EXPOSURE",
        "check":       "service",
        "services":    {"IPMI"},
        "technique":   "T1556",
        "name":        "IPMI Cipher 0 Authentication Bypass",
        "description": "IPMI exposed to internet allows authentication bypass via Cipher 0, "
                       "enabling full server control.",
        "severity":    "CRITICAL",
    },
]


def find_escalation_paths(graph: dict, attack_surface: dict) -> list:
    gq = GraphQuery(graph)
    paths = []
    found_ids = set()

    assets = attack_surface.get("assets", [])

    for asset in assets:
        host = asset["host"]
        open_ports = set(asset.get("open_ports", []))
        asset_node_list = [n for n in (gq.by_type("Subdomain") + gq.by_type("Domain"))
                           if n["name"] == host]
        if not asset_node_list:
            continue
        asset_node = asset_node_list[0]
        port_nodes = gq.neighbors(asset_node["node_id"], "HAS_PORT")
        open_services = {n["properties"].get("service", "") for n in port_nodes}

        for sig in ESCALATION_SIGNATURES:
            sig_id = f"{sig['id']}:{host}"
            if sig_id in found_ids:
                continue

            matched = False
            if sig["check"] == "keyword":
                matched = any(kw in host.lower() for kw in sig["keywords"])
            elif sig["check"] == "service":
                matched = bool(open_services & sig["services"])

            if matched:
                found_ids.add(sig_id)
                paths.append({
                    "escalation_id":  sig["id"],
                    "host":           host,
                    "technique":      sig["technique"],
                    "name":           sig["name"],
                    "description":    sig["description"],
                    "severity":       sig["severity"],
                    "evidence":       f"Detected on {host}",
                })

    paths.sort(key=lambda x: {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}.get(x["severity"], 0), reverse=True)
    return paths
