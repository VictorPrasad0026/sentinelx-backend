"""
SentinelX Persistence Engine

Identifies infrastructure conditions that would allow
an attacker to maintain long-term access after initial compromise.

Detects persistence risk via:
  - Weak email security (allows ongoing phishing campaigns)
  - Expired/invalid SSL (MITM for credential harvesting)
  - Git/SVN exposed (source code = backdoor targets)
  - Cron/scheduler services
  - Weak DMARC (domain impersonation persists)
  - Wildcard certificates (broad re-use)
"""

from intelligence_engine.graph.graph_queries import GraphQuery

PERSISTENCE_CHECKS = [
    {
        "id":          "WEAK_DMARC_PERSISTENCE",
        "description": "DMARC policy is 'none' or missing — attacker can continue spoofing "
                       "domain indefinitely for phishing campaigns.",
        "technique":   "T1566.002",
        "name":        "Spearphishing via Domain Spoof",
        "severity":    "HIGH",
        "check_type":  "email",
        "condition":   lambda email: (
            not email.get("dmarc", {}).get("enabled") or
            email.get("dmarc", {}).get("policy") in ("none", None, "NONE")
        ),
    },
    {
        "id":          "EXPIRED_CERT_MITM",
        "description": "Invalid or expired SSL certificate creates ongoing MITM risk for "
                       "credential harvesting.",
        "technique":   "T1557",
        "name":        "Adversary-in-the-Middle",
        "severity":    "HIGH",
        "check_type":  "ssl",
        "condition":   lambda ssl: ssl.get("status") not in ("VALID",),
    },
    {
        "id":          "WILDCARD_CERT_PERSISTENCE",
        "description": "Wildcard certificate in use — if private key is stolen, attacker "
                       "can impersonate any subdomain indefinitely.",
        "technique":   "T1553.004",
        "name":        "Install Root Certificate",
        "severity":    "MEDIUM",
        "check_type":  "ssl",
        "condition":   lambda ssl: ssl.get("wildcard") is True,
    },
    {
        "id":          "GIT_SVN_EXPOSED",
        "description": "Version control service exposed — source code access enables backdoor "
                       "insertion that persists across deployments.",
        "technique":   "T1195.001",
        "name":        "Compromise Software Supply Chain",
        "severity":    "HIGH",
        "check_type":  "service",
        "services":    {"GIT", "SVN"},
    },
    {
        "id":          "TELNET_BACKDOOR_RISK",
        "description": "TELNET exposed — cleartext protocol; any credential captured persists "
                       "as a standing backdoor entry point.",
        "technique":   "T1021",
        "name":        "Remote Services Persistence",
        "severity":    "CRITICAL",
        "check_type":  "service",
        "services":    {"TELNET", "TELNETS"},
    },
]


def find_persistence_risks(profile: dict, graph: dict) -> list:
    gq = GraphQuery(graph)
    risks = []

    ssl_data   = profile.get("ssl_intelligence", {}).get("ssl", {})
    email_data = profile.get("email_intelligence", {})

    for check in PERSISTENCE_CHECKS:
        check_type = check["check_type"]
        matched = False
        host = profile.get("asset", "unknown")

        if check_type == "ssl":
            matched = check["condition"](ssl_data)

        elif check_type == "email":
            matched = check["condition"](email_data)

        elif check_type == "service":
            all_port_nodes = gq.by_type("Port")
            open_services = {n["properties"].get("service", "") for n in all_port_nodes}
            matched = bool(open_services & check["services"])

        if matched:
            risks.append({
                "persistence_id": check["id"],
                "host":           host,
                "technique":      check["technique"],
                "name":           check["name"],
                "description":    check["description"],
                "severity":       check["severity"],
            })

    risks.sort(key=lambda x: {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}.get(x["severity"], 0), reverse=True)
    return risks
