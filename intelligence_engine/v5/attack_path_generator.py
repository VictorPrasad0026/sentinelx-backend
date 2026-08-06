"""
SentinelX V5 — Attack Path Generator

Generates complete, CVE-enriched attack paths by combining:
  - V4 attack chains (evidence-based)
  - V5 CVE data (EPSS + KEV)
  - TLS grades
  - Login page findings
  - Secret exposure findings
  - Passive DNS (historical assets)

Each path is scored on:
  - Technical likelihood (scan evidence)
  - Exploitability (EPSS score)
  - Business impact (asset criticality)
  - Attacker skill required (LOW/MEDIUM/HIGH)

Output format designed for graph visualisation:
  nodes[] + edges[] + chains[]
"""

from datetime import datetime, timezone


SKILL_LEVELS = {
    "script_kiddie": {"label": "Script Kiddie",  "desc": "Automated tools, no custom code"},
    "intermediate":  {"label": "Intermediate",   "desc": "Can modify exploits, basic scripting"},
    "advanced":      {"label": "Advanced",       "desc": "Custom exploits, deep knowledge"},
    "nation_state":  {"label": "Nation State",   "desc": "Zero-days, persistence, supply chain"},
}


def _merge_cve_into_chain(chain: dict, tech_vulns: list) -> dict:
    """
    If a chain targets a technology that has known CVEs, enrich the chain
    with CVE details, EPSS scores, and KEV status.
    """
    enriched = dict(chain)
    service = chain.get("service", "").lower()
    tech_map = {
        "wordpress": "WordPress",
        "apache":    "Apache",
        "nginx":     "Nginx",
        "mysql":     "MySQL",
        "mariadb":   "MariaDB",
        "php":       "PHP",
        "openssh":   "OpenSSH",
    }

    target_tech = tech_map.get(service, None)
    matched_vulns = []

    for tv in tech_vulns:
        if target_tech and tv.get("technology", "").lower() == target_tech.lower():
            matched_vulns = tv.get("cves", [])[:3]
            break

    if matched_vulns:
        enriched["cve_enriched"]  = True
        enriched["matched_cves"]  = matched_vulns
        enriched["top_epss"]      = max((c.get("epss_score", 0) for c in matched_vulns), default=0)
        enriched["kev_matched"]   = any(c.get("in_kev") for c in matched_vulns)

        # Boost likelihood if CVEs exist and have high EPSS
        epss_boost = round(enriched.get("top_epss", 0) * 15)
        enriched["likelihood"] = min(99, chain.get("likelihood", 0) + epss_boost)

        if enriched.get("kev_matched"):
            enriched["likelihood"] = min(99, enriched["likelihood"] + 10)

        # Update steps with CVE info
        for step in enriched.get("steps", []):
            if "CVE" in step.get("action", "") or "exploit" in step.get("action", "").lower():
                cve = matched_vulns[0]
                step["cve_id"]    = cve["cve_id"]
                step["cvss"]      = cve.get("cvss_score")
                step["epss"]      = cve.get("epss_score", 0)
                step["in_kev"]    = cve.get("in_kev", False)

    return enriched


def _assign_skill_level(chain: dict) -> str:
    likelihood = chain.get("likelihood", 0)
    kev        = chain.get("kev_matched", False)
    service    = chain.get("service", "").upper()

    if service in ("MYSQL", "POSTGRESQL", "REDIS", "MONGODB") and likelihood >= 80:
        return "script_kiddie"   # just a MySQL client
    if kev:
        return "script_kiddie"   # public exploits exist
    if likelihood >= 70:
        return "intermediate"
    if likelihood >= 50:
        return "advanced"
    return "advanced"


def _business_impact_score(chain: dict, exposure_map: dict) -> dict:
    entry   = chain.get("entry_point", "")
    exp     = exposure_map.get(entry, {}).get("exposure_score", 50)
    service = chain.get("service", "").upper()

    data_impact    = service in ("MYSQL", "POSTGRESQL", "MONGODB", "REDIS", "ELASTICSEARCH")
    network_impact = chain.get("service") in ("SSH", "RDP", "SMB")
    email_impact   = "EMAIL" in chain.get("chain_id", "").upper()

    financial   = "HIGH" if data_impact or email_impact else "MEDIUM"
    operational = "CRITICAL" if network_impact else "HIGH" if data_impact else "MEDIUM"
    reputation  = "HIGH" if data_impact else "MEDIUM"

    return {
        "financial":   financial,
        "operational": operational,
        "reputation":  reputation,
        "data_risk":   data_impact,
        "exposure_score": exp,
    }


def generate_attack_paths(v4_report: dict, vuln_report: dict,
                           tls_report: dict, login_report: list,
                           secrets_report: list) -> dict:
    """
    Combine V4 chains + V5 enrichment into complete prioritized attack paths.
    """
    chains       = v4_report.get("attack_graph", {}).get("attack_chains", [])
    tech_vulns   = vuln_report.get("by_technology", []) if isinstance(vuln_report, dict) else []
    exposure_map = {
        e["host"]: e
        for e in v4_report.get("attack_graph", {}).get("exposure_scores", [])
    }

    enriched_paths = []

    for chain in chains:
        enriched = _merge_cve_into_chain(chain, tech_vulns)
        enriched["skill_required"]    = _assign_skill_level(enriched)
        enriched["skill_label"]       = SKILL_LEVELS[enriched["skill_required"]]["label"]
        enriched["business_impact_detail"] = _business_impact_score(enriched, exposure_map)
        enriched["generated_at"]      = datetime.now(timezone.utc).isoformat()
        enriched_paths.append(enriched)

    # Add login-based attack paths
    for lr in (login_report or []):
        if isinstance(lr, dict):
            for login in lr.get("login_pages", []):
                if login.get("default_creds_risk"):
                    panel = login.get("panel_type", "Admin panel")
                    chain = {
                        "chain_id":     f"DEFAULT_CREDS_{panel.upper().replace(' ','_')}",
                        "name":         f"Default Credentials — {panel}",
                        "entry_point":  lr.get("host", "unknown"),
                        "service":      panel,
                        "port":         login.get("path", ""),
                        "steps": [
                            {"step": 1, "actor": "Internet", "action": f"Discover {panel} at {login['url']}", "technique": "T1595"},
                            {"step": 2, "actor": "Attacker", "action": f"Try known defaults: {', '.join(login.get('known_defaults', [])[:2])}", "technique": "T1110.001 — Default Credentials"},
                            {"step": 3, "actor": panel, "action": "Gain administrative access", "technique": "T1078 — Valid Accounts"},
                        ],
                        "likelihood":   85,
                        "confidence":   "HIGH",
                        "mitre_chain":  ["T1595", "T1110.001", "T1078"],
                        "business_impact": f"Full {panel} admin access without credentials",
                        "skill_required":  "script_kiddie",
                        "skill_label":     "Script Kiddie",
                        "evidence":     [f"Panel: {panel}", f"URL: {login['url']}", f"Defaults: {login.get('known_defaults', [])}"],
                    }
                    chain["business_impact_detail"] = {"financial": "HIGH", "operational": "CRITICAL", "data_risk": True, "exposure_score": 90}
                    enriched_paths.append(chain)

    # Add secrets-based paths
    for sr in (secrets_report or []):
        if isinstance(sr, dict):
            for f in sr.get("files_exposed", []):
                if f.get("severity") == "CRITICAL" and f.get("secrets_keys"):
                    chain = {
                        "chain_id":    f"SECRET_EXPOSURE_{f['path'].replace('/','_').upper()}",
                        "name":        f"Exposed Secret: {f['path']}",
                        "entry_point": sr.get("host", "unknown"),
                        "service":     "HTTP",
                        "port":        443,
                        "steps": [
                            {"step": 1, "actor": "Internet", "action": f"Request {f['url']}", "technique": "T1595"},
                            {"step": 2, "actor": "File", "action": f"Read credentials: {', '.join(f['secrets_keys'])}", "technique": "T1552.001 — Credentials In Files"},
                            {"step": 3, "actor": "Attacker", "action": "Use extracted credentials to access backend systems", "technique": "T1078"},
                        ],
                        "likelihood":  90,
                        "confidence":  "CRITICAL",
                        "mitre_chain": ["T1595", "T1552.001", "T1078"],
                        "business_impact": f"Credentials from {f['path']} enable direct backend access",
                        "skill_required": "script_kiddie",
                        "skill_label":    "Script Kiddie",
                        "evidence":    [f"File: {f['url']}", f"Secret keys: {f['secrets_keys']}"],
                    }
                    chain["business_impact_detail"] = {"financial": "CRITICAL", "operational": "CRITICAL", "data_risk": True, "exposure_score": 100}
                    enriched_paths.append(chain)

    # Sort by likelihood descending
    enriched_paths.sort(key=lambda x: x.get("likelihood", 0), reverse=True)
    for i, p in enumerate(enriched_paths):
        p["rank"] = i + 1

    critical = [p for p in enriched_paths if p.get("likelihood", 0) >= 80]
    kev_paths = [p for p in enriched_paths if p.get("kev_matched")]

    return {
        "total_paths":    len(enriched_paths),
        "critical_paths": len(critical),
        "kev_paths":      len(kev_paths),
        "attack_paths":   enriched_paths,
        "summary": {
            "top_path":        enriched_paths[0]["name"] if enriched_paths else None,
            "top_likelihood":  enriched_paths[0].get("likelihood") if enriched_paths else None,
            "skill_kiddie":    sum(1 for p in enriched_paths if p.get("skill_required") == "script_kiddie"),
            "skill_advanced":  sum(1 for p in enriched_paths if p.get("skill_required") == "advanced"),
        },
    }
