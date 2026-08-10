"""
SentinelX V4 — Internet Exposure Scoring Engine  v2
FIXED:
  P4 — scores are now labelled "v4_exposure_score" to distinguish from
       graph/intelligence engine scores which use "graph_exposure_score".
       Both are returned but clearly named so UI never shows unlabelled duplicates.
"""

NEVER_EXPOSE = {
    3306:  ("MySQL",         40),
    5432:  ("PostgreSQL",    40),
    6379:  ("Redis",         45),
    27017: ("MongoDB",       45),
    9200:  ("Elasticsearch", 45),
    2375:  ("Docker API",    50),
    10250: ("Kubernetes",    50),
    445:   ("SMB",           40),
    3389:  ("RDP",           35),
    23:    ("Telnet",        45),
    4444:  ("Metasploit",    50),
    31337: ("Backdoor",      50),
}

SENSITIVE_EXPOSE = {
    21:   ("FTP",       15),
    22:   ("SSH",       10),
    1723: ("PPTP VPN",  20),
    1433: ("MSSQL",     40),
    5900: ("VNC",       30),
    8009: ("AJP",       35),
    623:  ("IPMI",      40),
}

DATA_SENSITIVE_KEYWORDS = [
    "exam", "admission", "result", "student", "crm",
    "hr", "finance", "payroll", "erp", "db", "database",
]

ADMIN_KEYWORDS = [
    "admin", "panel", "dashboard", "manage", "control",
    "portal", "login", "auth", "sso",
]


def score_asset_exposure(host: str, open_ports: list,
                          waf: bool, cdn: bool, ssl_valid: bool,
                          has_hsts: bool, has_csp: bool,
                          cloud_provider: str) -> dict:
    score = 0
    factors = []
    host_lower = host.lower()

    for port in open_ports:
        if port in NEVER_EXPOSE:
            name, pts = NEVER_EXPOSE[port]
            score += pts
            factors.append({"factor": f"Critical service exposed: {name} (port {port})",
                            "points": pts, "severity": "CRITICAL"})

    for port in open_ports:
        if port in SENSITIVE_EXPOSE:
            name, pts = SENSITIVE_EXPOSE[port]
            score += pts
            factors.append({"factor": f"Sensitive service exposed: {name} (port {port})",
                            "points": pts, "severity": "HIGH"})

    if not waf:
        score += 8
        factors.append({"factor": "No WAF protection", "points": 8, "severity": "MEDIUM"})

    if not cdn:
        score += 5
        factors.append({"factor": "No CDN — origin IP directly exposed", "points": 5, "severity": "LOW"})

    if not ssl_valid:
        score += 15
        factors.append({"factor": "Invalid SSL certificate", "points": 15, "severity": "HIGH"})

    if not has_hsts:
        score += 5
        factors.append({"factor": "Missing HSTS header", "points": 5, "severity": "LOW"})

    if not has_csp:
        score += 5
        factors.append({"factor": "Missing Content Security Policy", "points": 5, "severity": "LOW"})

    if any(kw in host_lower for kw in DATA_SENSITIVE_KEYWORDS):
        score += 10
        factors.append({"factor": "Data-sensitive asset (exam/admission/CRM)", "points": 10, "severity": "HIGH"})

    if any(kw in host_lower for kw in ADMIN_KEYWORDS):
        score += 10
        factors.append({"factor": "Admin interface internet-facing", "points": 10, "severity": "HIGH"})

    extra_ports = max(0, len(open_ports) - 3)
    if extra_ports > 0:
        pts = min(extra_ports * 2, 10)
        score += pts
        factors.append({"factor": f"{len(open_ports)} open ports (excessive exposure)",
                        "points": pts, "severity": "MEDIUM"})

    score = min(score, 100)

    if score >= 70:
        level = "CRITICAL"
    elif score >= 45:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "host":              host,
        # P4 FIX: clearly labelled as V4 score, not a generic "exposure_score"
        "v4_exposure_score": score,
        "exposure_level":    level,
        "scoring_engine":    "V4 Port+SSL+WAF Model",   # P4: label which engine
        "factors":           factors,
        # Keep legacy key for backward compat with existing code
        "exposure_score":    score,
    }


def score_all_assets(correlated_assets: list) -> list:
    results = []
    for asset in correlated_assets:
        host      = asset["host"]
        ports     = asset.get("open_ports", [])
        waf       = False
        cdn       = asset.get("cloud") in ("AWS CloudFront", "Cloudflare", "Akamai")
        ssl_valid = True
        has_hsts  = True
        has_csp   = True

        for f in asset.get("findings", []):
            issue = f.get("issue", "").lower()
            if "ssl" in issue and "invalid" in issue:
                ssl_valid = False
            if "hsts" in issue or "strict-transport" in issue:
                has_hsts = False
            if "csp" in issue or "content security" in issue:
                has_csp = False

        scored = score_asset_exposure(host, ports, waf, cdn, ssl_valid,
                                       has_hsts, has_csp, asset.get("cloud", "UNKNOWN"))
        results.append(scored)

    results.sort(key=lambda x: x["v4_exposure_score"], reverse=True)
    return results
