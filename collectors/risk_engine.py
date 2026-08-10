"""
SentinelX ASM Risk Engine v4
FIXED:
  P1 — Score aggregation: now rolls up asset-level findings + exposure scores
  P2 — SSL misattribution: every finding carries source host
  P5 — Disabled module tracking: returns scan_coverage block
"""

from datetime import datetime


# =====================================================
# FINDING CREATOR  (now includes source host)
# =====================================================

def add_finding(findings, category, issue, severity, score,
                confidence="MEDIUM", impact="TECHNICAL",
                recommendation="", host=None):
    findings.append({
        "category":       category,
        "issue":          issue,
        "severity":       severity,
        "score":          score,
        "confidence":     confidence,
        "impact":         impact,
        "recommendation": recommendation,
        "host":           host,          # P2 FIX: always carry source asset
    })


# =====================================================
# ASSET CRITICALITY
# =====================================================

def analyze_asset_criticality(profile, findings):
    score = 0
    domain = profile.get("asset", "").lower()
    keywords = ["admin", "login", "portal", "api", "vpn", "mail", "erp", "cloud"]
    for kw in keywords:
        if kw in domain:
            add_finding(findings, "Asset Criticality",
                        f"Critical asset keyword detected: {kw}",
                        "HIGH", 10, "HIGH", "BUSINESS",
                        "Review exposure and access controls",
                        host=domain)
            score += 10
            break
    return min(score, 15)


# =====================================================
# SSL SECURITY  (P2 FIX: host passed in, carried on finding)
# =====================================================

def analyze_ssl(profile, findings, host=None):
    score = 0
    ssl = profile.get("ssl_intelligence", {})
    source = host or profile.get("asset", "unknown")

    if not ssl:
        add_finding(findings, "SSL", "SSL information unavailable",
                    "MEDIUM", 10, host=source)
        return 10

    if ssl.get("status") != "VALID":
        add_finding(findings, "SSL", "Invalid SSL certificate",
                    "HIGH", 20, "HIGH", "TECHNICAL",
                    "Renew or fix certificate chain",
                    host=source)          # P2 FIX: source is the real host, not root domain
        score += 20

    tls = ssl.get("tls_version")
    if tls in ("TLSv1", "TLSv1.1"):
        add_finding(findings, "SSL", f"Weak TLS version {tls}",
                    "HIGH", 15, "HIGH", "TECHNICAL",
                    "Upgrade TLS configuration",
                    host=source)
        score += 15

    return score


# =====================================================
# CERTIFICATE EXPIRY
# =====================================================

def analyze_certificate_expiry(profile, findings, host=None):
    ssl = profile.get("ssl_intelligence", {})
    expiry = ssl.get("valid_until")
    source = host or profile.get("asset", "unknown")
    if not expiry:
        return 0
    try:
        cert_date = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z")
        days = (cert_date - datetime.utcnow()).days
        if days < 15:
            add_finding(findings, "SSL", f"Certificate expires in {days} days",
                        "HIGH", 15, "HIGH", "OPERATIONAL", "Renew certificate",
                        host=source)
            return 15
        elif days < 30:
            add_finding(findings, "SSL", f"Certificate expires soon ({days} days)",
                        "MEDIUM", 8, host=source)
            return 8
    except Exception:
        pass
    return 0


# =====================================================
# SECURITY HEADERS
# =====================================================

def analyze_headers(profile, findings, host=None):
    score = 0
    source = host or profile.get("asset", "unknown")
    tech = profile.get("technology_intelligence", {})
    headers = tech.get("security_headers", {})
    checks = {
        "strict-transport-security": 4,
        "content-security-policy":   5,
        "x-frame-options":           3,
        "x-content-type-options":    3,
        "referrer-policy":           2,
        "permissions-policy":        2,
    }
    for header, pts in checks.items():
        data = headers.get(header, {})
        if not data.get("present", False):
            add_finding(findings, "Security Headers", f"Missing {header}",
                        "MEDIUM", pts, "MEDIUM", "TECHNICAL",
                        f"Implement {header}", host=source)
            score += pts
    return min(score, 25)


# =====================================================
# CSP
# =====================================================

def analyze_csp(profile, findings, host=None):
    source = host or profile.get("asset", "unknown")
    csp = profile.get("csp_intelligence", {})
    if not csp.get("enabled", False):
        add_finding(findings, "CSP", "Content Security Policy missing",
                    "MEDIUM", 10, "HIGH", "TECHNICAL", "Deploy restrictive CSP",
                    host=source)
        return 10
    if csp.get("risk_level", "").upper() == "HIGH":
        add_finding(findings, "CSP", "Unsafe CSP configuration",
                    "HIGH", 10, "MEDIUM", "TECHNICAL", "Remove unsafe directives",
                    host=source)
        return 10
    return 0


# =====================================================
# EMAIL SECURITY
# =====================================================

def analyze_email(profile, findings, host=None):
    score = 0
    source = host or profile.get("asset", "unknown")
    email = profile.get("email_intelligence", {})
    if not email:
        return 0
    if email.get("dmarc", {}).get("policy") == "none":
        add_finding(findings, "Email Security", "DMARC policy monitoring only",
                    "MEDIUM", 8, "HIGH", "BUSINESS",
                    "Move DMARC policy to quarantine/reject", host=source)
        score += 8
    if email.get("dkim", {}).get("status") == "NOT_FOUND":
        add_finding(findings, "Email Security", "DKIM selector not detected",
                    "MEDIUM", 5, "MEDIUM", "TECHNICAL", "Enable DKIM signing",
                    host=source)
        score += 5
    return score


# =====================================================
# SUBDOMAINS
# =====================================================

def analyze_subdomains(profile, findings):
    score = 0
    assets = profile.get("subdomain_assets", {}).get("assets", [])
    sensitive = ["admin", "dev", "test", "staging", "backup", "vpn", "internal", "api"]
    for asset in assets:
        host = asset.get("host", "").lower()
        for word in sensitive:
            if word in host:
                add_finding(findings, "Attack Surface",
                            f"Sensitive subdomain exposed: {host}",
                            "HIGH", 10, "HIGH", "BUSINESS",
                            "Review external exposure", host=host)
                score += 10
                break
    return min(score, 25)


# =====================================================
# TECHNOLOGY
# =====================================================

def analyze_technology(profile, findings, host=None):
    score = 0
    source = host or profile.get("asset", "unknown")
    tech = profile.get("technology_intelligence", {})
    raw = tech.get("technologies", [])
    technologies = [(x["name"].lower() if isinstance(x, dict) else x.lower()) for x in raw]
    for item in ("wordpress", "apache", "nginx"):
        if item in technologies:
            add_finding(findings, "Technology",
                        f"Technology fingerprint exposed: {item}",
                        "LOW", 3, "LOW", "TECHNICAL",
                        "Review version and vulnerabilities", host=source)
            score += 3
    return min(score, 10)


# =====================================================
# DNS
# =====================================================

def analyze_dns(profile, findings):
    source = profile.get("asset", "unknown")
    dns = profile.get("dns_intelligence", {})
    if dns.get("error"):
        add_finding(findings, "DNS", "DNS resolution failure",
                    "LOW", 5, host=source)
        return 5
    return 0


# =====================================================
# P1 FIX: ASSET-LEVEL ROLLUP
# Scans every subdomain asset, runs risk checks per-asset,
# then rolls the worst score up to the root assessment.
# =====================================================

def _score_per_asset(asset: dict) -> tuple:
    """
    Run SSL + header + CSP checks on a single subdomain asset profile.
    Returns (score, findings_list).
    """
    sub_findings = []
    host = asset.get("host", "unknown")
    sub_score = 0

    # Build a mini-profile from the asset's data
    sub_profile = {
        "asset": host,
        "ssl_intelligence":     asset.get("ssl_intelligence", {}),
        "technology_intelligence": asset.get("technology_intelligence", {}),
        "csp_intelligence":     asset.get("csp_intelligence", {}),
    }

    sub_score += analyze_ssl(sub_profile, sub_findings, host=host)
    sub_score += analyze_certificate_expiry(sub_profile, sub_findings, host=host)
    sub_score += analyze_headers(sub_profile, sub_findings, host=host)
    sub_score += analyze_csp(sub_profile, sub_findings, host=host)

    # Also pull any pre-computed risk score from asset correlation
    asset_risk_score = asset.get("risk", {}).get("score", 0)
    sub_score = max(sub_score, asset_risk_score)

    # CRITICAL service ports boost score
    open_ports = asset.get("open_ports", [])
    critical_ports = {3306, 5432, 6379, 27017, 9200, 2375, 3389, 23, 445}
    for port in open_ports:
        if port in critical_ports:
            sub_score = max(sub_score, 80)   # floor at CRITICAL
            add_finding(sub_findings, "Infrastructure",
                        f"Critical service port {port} open to internet on {host}",
                        "CRITICAL", 80, "HIGH", "BUSINESS",
                        f"Firewall port {port} — never expose to internet",
                        host=host)
            break

    return min(sub_score, 100), sub_findings


def rollup_asset_scores(profile: dict, root_findings: list) -> tuple:
    """
    P1 FIX: aggregate root domain score + all asset scores.
    Returns (final_score, all_findings_combined).
    """
    assets = profile.get("subdomain_assets", {}).get("assets", [])
    all_findings = list(root_findings)
    asset_scores = []

    for asset in assets:
        a_score, a_findings = _score_per_asset(asset)
        asset_scores.append((asset.get("host", "?"), a_score))
        all_findings.extend(a_findings)

    # Also pull exposure scores if V4 already computed them
    exposure_scores = []
    for asset in assets:
        exp = asset.get("exposure_score", None)
        if exp is not None:
            exposure_scores.append(exp)

    # Final score = weighted: root 40% + worst asset 60%
    root_score = sum(f.get("score", 0) for f in root_findings)
    root_score = min(root_score, 100)

    worst_asset_score = max((s for _, s in asset_scores), default=0)
    worst_exposure    = max(exposure_scores, default=0)
    worst_asset_score = max(worst_asset_score, worst_exposure)

    # P1 CORE FIX: weighted aggregation
    if asset_scores:
        final_score = int(root_score * 0.4 + worst_asset_score * 0.6)
    else:
        final_score = root_score

    final_score = min(final_score, 100)

    return final_score, all_findings, asset_scores


# =====================================================
# P5 FIX: SCAN COVERAGE TRACKER
# =====================================================

def build_scan_coverage(options: dict = None) -> dict:
    options = options or {}
    modules = {
        "subdomain_enum":         True,
        "dns_intelligence":       True,
        "ssl_analysis":           True,
        "http_fingerprinting":    True,
        "technology_detection":   True,
        "email_security":         True,
        "asset_correlation":      True,
        "attack_graph":           True,
        "tls_grading":            True,
        "login_detection":        options.get("enable_login_scan", True),
        "secrets_exposure":       options.get("enable_secrets_scan", True),
        "vulnerability_intel":    options.get("enable_vuln_intel", False),
        "js_intelligence":        options.get("enable_js_intel", False),
        "passive_dns":            options.get("enable_passive_dns", True),
        "screenshots":            options.get("enable_screenshots", False),
        "github_leaks":           options.get("enable_github", False),
        "ct_timeline":            options.get("enable_ct_timeline", True),
    }
    enabled  = [k for k, v in modules.items() if v]
    disabled = [k for k, v in modules.items() if not v]

    coverage_pct = int(len(enabled) / len(modules) * 100)

    banner = None
    if disabled:
        pretty = [d.replace("_", " ").title() for d in disabled]
        banner = (
            f"⚠️  SCAN COVERAGE: {len(enabled)}/{len(modules)} modules active ({coverage_pct}%). "
            f"Disabled: {', '.join(pretty)}. "
            f"Results may underrepresent actual risk — vulnerability data, "
            f"JS analysis, and leak scanning are incomplete."
        )

    return {
        "total_modules":    len(modules),
        "enabled_count":    len(enabled),
        "disabled_count":   len(disabled),
        "coverage_percent": coverage_pct,
        "enabled_modules":  enabled,
        "disabled_modules": disabled,
        "coverage_banner":  banner,
    }


# =====================================================
# MAIN RISK ENGINE  (all priorities fixed)
# =====================================================

def calculate_risk(profile, options: dict = None):
    findings = []
    score    = 0
    options  = options or {}

    # Root-domain checks
    modules = [
        analyze_asset_criticality,
        lambda p, f: analyze_ssl(p, f, host=p.get("asset")),
        lambda p, f: analyze_certificate_expiry(p, f, host=p.get("asset")),
        lambda p, f: analyze_headers(p, f, host=p.get("asset")),
        lambda p, f: analyze_csp(p, f, host=p.get("asset")),
        analyze_email,
        analyze_subdomains,
        lambda p, f: analyze_technology(p, f, host=p.get("asset")),
        analyze_dns,
    ]

    for module in modules:
        score += module(profile, findings)

    # P1 FIX: roll up asset-level scores
    final_score, all_findings, asset_breakdown = rollup_asset_scores(profile, findings)

    # Severity from final rolled-up score
    if final_score >= 75:
        severity = "CRITICAL"
    elif final_score >= 50:
        severity = "HIGH"
    elif final_score >= 25:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # P1 FIX: critical_findings counts ALL findings across all assets
    critical_count = len([f for f in all_findings if f["severity"] == "CRITICAL"])
    high_count     = len([f for f in all_findings if f["severity"] == "HIGH"])

    # P5 FIX: scan coverage
    coverage = build_scan_coverage(options)

    return {
        "engine":                "SentinelX ASM Risk Engine v4",
        "risk_score":            final_score,
        "severity":              severity,
        "total_findings":        len(all_findings),
        "scan_time":             datetime.utcnow().isoformat() + "Z",
        "findings":              all_findings,
        "asset_score_breakdown": asset_breakdown,   # per-asset scores for UI
        "scan_coverage":         coverage,          # P5: disabled module banner
        "summary": {
            "critical_findings":  critical_count,   # P1 FIX: from all assets
            "high_findings":      high_count,
            "recommendation":     "Prioritize internet-exposed assets and CRITICAL findings first",
        },
    }


if __name__ == "__main__":
    print("SentinelX ASM Risk Engine v4 Loaded")
