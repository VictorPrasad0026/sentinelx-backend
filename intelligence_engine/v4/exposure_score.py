"""
SentinelX V4 — Internet Exposure Scoring Engine

Scores every asset 0-100 like Wiz / Cortex Xpanse.

Factors:
  1. Internet exposure        (open ports, count, risk)
  2. Sensitive service        (DB, admin, VPN exposed)
  3. Authentication weakness  (no WAF, weak SSL)
  4. Cloud exposure           (direct IP, no CDN)
  5. Data sensitivity         (admission, exam, CRM)
  6. Missing protections      (no HSTS, no CSP)
"""

# Ports that should never be internet-facing
NEVER_EXPOSE = {
    3306: ("MySQL",        40),
    5432: ("PostgreSQL",   40),
    6379: ("Redis",        45),
    27017:("MongoDB",      45),
    9200: ("Elasticsearch",45),
    2375: ("Docker API",   50),
    10250:("Kubernetes",   50),
    445:  ("SMB",          40),
    3389: ("RDP",          35),
    23:   ("Telnet",       45),
    4444: ("Metasploit",   50),
    31337:("Backdoor",     50),
}

SENSITIVE_EXPOSE = {
    21:   ("FTP",          15),
    22:   ("SSH",          10),
    1723: ("PPTP VPN",     20),
    1433: ("MSSQL",        40),
    5900: ("VNC",          30),
    8009: ("AJP",          35),
    623:  ("IPMI",         40),
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

    # 1. NEVER-EXPOSE ports
    for port in open_ports:
        if port in NEVER_EXPOSE:
            name, pts = NEVER_EXPOSE[port]
            score += pts
            factors.append({
                "factor":  f"Critical service exposed: {name} (port {port})",
                "points":  pts,
                "severity": "CRITICAL",
            })

    # 2. Sensitive ports
    for port in open_ports:
        if port in SENSITIVE_EXPOSE:
            name, pts = SENSITIVE_EXPOSE[port]
            score += pts
            factors.append({
                "factor":  f"Sensitive service exposed: {name} (port {port})",
                "points":  pts,
                "severity": "HIGH",
            })

    # 3. No WAF protection
    if not waf:
        score += 8
        factors.append({"factor": "No WAF protection", "points": 8, "severity": "MEDIUM"})

    # 4. No CDN (direct IP exposure)
    if not cdn:
        score += 5
        factors.append({"factor": "No CDN — origin IP directly exposed", "points": 5, "severity": "LOW"})

    # 5. SSL issue
    if not ssl_valid:
        score += 15
        factors.append({"factor": "Invalid SSL certificate", "points": 15, "severity": "HIGH"})

    # 6. Missing HSTS
    if not has_hsts:
        score += 5
        factors.append({"factor": "Missing HSTS header", "points": 5, "severity": "LOW"})

    # 7. Missing CSP
    if not has_csp:
        score += 5
        factors.append({"factor": "Missing Content Security Policy", "points": 5, "severity": "LOW"})

    # 8. Data sensitivity boost
    if any(kw in host_lower for kw in DATA_SENSITIVE_KEYWORDS):
        score += 10
        factors.append({"factor": "Data-sensitive asset (exam/admission/CRM)", "points": 10, "severity": "HIGH"})

    # 9. Admin interface
    if any(kw in host_lower for kw in ADMIN_KEYWORDS):
        score += 10
        factors.append({"factor": "Admin interface internet-facing", "points": 10, "severity": "HIGH"})

    # 10. Total open ports volume
    extra_ports = max(0, len(open_ports) - 3)
    if extra_ports > 0:
        pts = min(extra_ports * 2, 10)
        score += pts
        factors.append({"factor": f"{len(open_ports)} open ports (excessive exposure)", "points": pts, "severity": "MEDIUM"})

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
        "host":           host,
        "exposure_score": score,
        "exposure_level": level,
        "factors":        factors,
    }


def score_all_assets(correlated_assets: list) -> list:
    results = []
    for asset in correlated_assets:
        host       = asset["host"]
        ports      = asset.get("open_ports", [])
        waf        = False   # extracted from HTTP data below
        cdn        = asset.get("cloud") in ("AWS CloudFront", "Cloudflare", "Akamai")
        ssl_valid  = True    # set to True as default; risk engine already flags it
        has_hsts   = True    # default; risk findings already track this
        has_csp    = True

        # Derive from findings
        for f in asset.get("findings", []):
            issue = f.get("issue", "").lower()
            if "ssl" in issue and "invalid" in issue:
                ssl_valid = False
            if "hsts" in issue or "strict-transport" in issue:
                has_hsts = False
            if "csp" in issue or "content security" in issue:
                has_csp = False

        scored = score_asset_exposure(
            host, ports, waf, cdn, ssl_valid, has_hsts, has_csp,
            asset.get("cloud", "UNKNOWN")
        )
        results.append(scored)

    results.sort(key=lambda x: x["exposure_score"], reverse=True)
    return results
