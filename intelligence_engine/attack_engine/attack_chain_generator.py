"""
SentinelX Attack Chain Generator

Composes individual attack paths into multi-stage chains.
Example: Web Exploit → Credential Theft → Lateral Movement → Database

Input : ranked attack paths from attack_path_builder + attack_path_ranker
Output: list of chained attack scenarios with combined likelihood
"""

CHAIN_TEMPLATES = [
    {
        "chain_id":   "WEB_TO_DATABASE",
        "name":       "Web Application to Database Compromise",
        "description": "Attacker exploits a public web service, pivots to backend database.",
        "entry_services":  {"HTTP", "HTTPS", "HTTP-ALT", "HTTPS-ALT"},
        "pivot_services":  {"MYSQL", "POSTGRESQL", "MSSQL", "ORACLE-DB", "MONGODB"},
        "mitre_chain": ["T1190", "T1552", "T1213"],
    },
    {
        "chain_id":   "CONTAINER_ESCAPE",
        "name":       "Container API to Host Takeover",
        "description": "Exposed Docker/Kubernetes API leads to container escape and host compromise.",
        "entry_services":  {"DOCKER-API", "KUBE-API", "DOCKER-TLS"},
        "pivot_services":  {"SSH", "MYSQL", "REDIS"},
        "mitre_chain": ["T1610", "T1611", "T1552"],
    },
    {
        "chain_id":   "EMAIL_PHISHING_TO_ADMIN",
        "name":       "Email Spoof to Admin Panel Compromise",
        "description": "Weak email security enables domain spoofing; attacker phishes admin credentials.",
        "entry_services":  {"SMTP", "SMTP-SUBMIT"},
        "pivot_services":  set(),
        "mitre_chain": ["T1566", "T1078", "T1133"],
        "requires_keyword": "admin",
    },
    {
        "chain_id":   "WINDOWS_LATERAL",
        "name":       "RDP/SMB Lateral Movement to Domain Controller",
        "description": "Exposed RDP or SMB enables password spraying, lateral movement, domain admin escalation.",
        "entry_services":  {"RDP", "SMB", "WINRM-HTTP", "WINRM-HTTPS"},
        "pivot_services":  {"LDAP", "LDAPS", "KERBEROS", "GC-LDAP"},
        "mitre_chain": ["T1021.001", "T1021.002", "T1558", "T1078"],
    },
    {
        "chain_id":   "CACHE_CREDENTIAL_THEFT",
        "name":       "Exposed Cache to Credential Theft",
        "description": "Redis/Elasticsearch without auth exposes session tokens and cached credentials.",
        "entry_services":  {"REDIS", "ELASTICSEARCH", "MEMCACHED"},
        "pivot_services":  set(),
        "mitre_chain": ["T1530", "T1552.001"],
    },
]


def generate_attack_chains(ranked_paths: list) -> list:
    """
    Takes the already-built ranked paths and matches them into multi-step chains.
    Returns list of chain dicts sorted by combined_likelihood.
    """
    chains = []

    path_by_service: dict[str, list] = {}
    for p in ranked_paths:
        svc = p.get("service", "")
        path_by_service.setdefault(svc, []).append(p)

    for template in CHAIN_TEMPLATES:
        entry_paths = [
            p for svc in template["entry_services"]
            for p in path_by_service.get(svc, [])
        ]

        if not entry_paths:
            continue

        # Optional keyword filter (e.g. admin panel)
        kw = template.get("requires_keyword")
        if kw:
            entry_paths = [p for p in entry_paths if kw in p.get("entry_point", "").lower()]
        if not entry_paths:
            continue

        pivot_paths = [
            p for svc in template.get("pivot_services", set())
            for p in path_by_service.get(svc, [])
        ]

        best_entry = max(entry_paths, key=lambda x: x.get("likelihood", 0))
        best_pivot = max(pivot_paths, key=lambda x: x.get("likelihood", 0)) if pivot_paths else None

        steps = [best_entry]
        if best_pivot:
            steps.append(best_pivot)

        # Combined likelihood: entry * 0.7 (pivot makes it harder)
        combined = round(best_entry.get("likelihood", 0) * (0.7 if best_pivot else 1.0), 1)

        affected = list({p.get("entry_point") for p in steps if p.get("entry_point")})

        chains.append({
            "chain_id":            template["chain_id"],
            "name":                template["name"],
            "description":         template["description"],
            "steps":               steps,
            "mitre_chain":         template["mitre_chain"],
            "combined_likelihood": combined,
            "affected_assets":     affected,
            "step_count":          len(steps),
        })

    chains.sort(key=lambda x: x["combined_likelihood"], reverse=True)
    return chains
