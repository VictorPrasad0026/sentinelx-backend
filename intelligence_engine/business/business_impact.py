"""
SentinelX Business Impact Engine  v2
FIXED:
  P1 — critical_findings_count now reads from ALL findings (root + assets)
  P6 — executive summary leads with highest-severity ASSET finding, not domain finding
"""

SEVERITY_TO_EXEC = {
    "CRITICAL": "immediately exploitable",
    "HIGH":     "high-risk condition requiring urgent attention",
    "MEDIUM":   "security gap that should be addressed",
    "LOW":      "minor hardening opportunity",
}

CATEGORY_TEMPLATES = {
    "SSL": (
        "The SSL/TLS configuration on {asset} has a {severity} issue. "
        "An attacker intercepting network traffic could read or modify sensitive data "
        "transmitted between your users and this service."
    ),
    "Security Headers": (
        "{asset} is missing browser security controls. "
        "This increases the risk of client-side attacks (XSS, clickjacking) "
        "that could compromise user sessions or steal credentials."
    ),
    "Email Security": (
        "Your email security configuration ({issue}) could allow attackers "
        "to send convincing phishing emails that appear to come from your domain. "
        "This directly threatens employee and customer trust."
    ),
    "Infrastructure": (
        "{asset} exposes {issue} to the internet. "
        "An attacker who gains access could potentially reach internal systems, "
        "extract sensitive data, or disrupt business operations."
    ),
    "Attack Surface": (
        "{asset} is a sensitive internal resource exposed to the internet. "
        "If compromised, it could provide attackers with direct access to "
        "internal infrastructure or sensitive business data."
    ),
    "CSP": (
        "{asset} lacks a Content Security Policy. "
        "This reduces browser-level protection against code injection attacks "
        "that could steal user data or credentials."
    ),
    "default": (
        "{asset} has a security issue: {issue}. "
        "This represents a {severity} risk to business operations."
    ),
}

COMPLIANCE_MAP = {
    "SSL":              ["PCI DSS 4.0 (6.4.1)", "ISO 27001 A.10.1", "GDPR Art.32"],
    "Security Headers": ["OWASP ASVS 3.4", "PCI DSS 6.4"],
    "Email Security":   ["DMARC Best Practice", "NIST SP 800-45"],
    "Infrastructure":   ["PCI DSS 1.3", "ISO 27001 A.13.1", "CIS Controls 12"],
    "Attack Surface":   ["CIS Controls 1", "ISO 27001 A.8"],
    "CSP":              ["OWASP ASVS 1.14", "PCI DSS 6.4"],
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def translate_finding(finding: dict, asset: str) -> dict:
    # P2 carry-through: use finding's own host if set, else fallback to asset arg
    source = finding.get("host") or asset
    category = finding.get("category", "default")
    issue    = finding.get("issue", "Unknown issue")
    severity = finding.get("severity", "MEDIUM")
    rec      = finding.get("recommendation", "Review and remediate")

    template = CATEGORY_TEMPLATES.get(category, CATEGORY_TEMPLATES["default"])
    exec_text = template.format(
        asset=source,
        issue=issue.lower(),
        severity=SEVERITY_TO_EXEC.get(severity, severity.lower()),
    )

    return {
        "technical_finding": issue,
        "executive_summary": exec_text,
        "category":          category,
        "severity":          severity,
        "source_host":       source,      # P2: always present
        "compliance_risk":   COMPLIANCE_MAP.get(category, []),
        "recommendation":    rec,
        "estimated_effort":  _estimate_effort(category, severity),
        "operational_risk":  _operational_risk(severity),
        "financial_risk":    _financial_risk(category, severity),
    }


def generate_business_impact(profile: dict, attack_paths: list) -> dict:
    risk    = profile.get("risk_assessment", {})
    domain  = profile.get("asset", "unknown")

    # P1 FIX: use ALL findings from the risk assessment (which now includes asset rollup)
    all_findings = risk.get("findings", [])

    # P6 FIX: sort findings by severity before translating — CRITICAL assets lead
    all_findings_sorted = sorted(
        all_findings,
        key=lambda f: (SEVERITY_ORDER.get(f.get("severity", "LOW"), 3),
                       0 if f.get("host", domain) != domain else 1)
        # asset-level findings (host != root domain) float to top within same severity
    )

    translated = [translate_finding(f, domain) for f in all_findings_sorted]

    critical = [t for t in translated if t["severity"] == "CRITICAL"]
    high     = [t for t in translated if t["severity"] == "HIGH"]
    medium   = [t for t in translated if t["severity"] == "MEDIUM"]

    top_path_exec = None
    if attack_paths:
        top = attack_paths[0]
        top_path_exec = (
            f"The most likely attack scenario starts at {top.get('entry_point', 'unknown')} "
            f"via {top.get('service', 'unknown')} (port {top.get('port', '?')}). "
            f"Business impact: {top.get('business_impact', 'Unknown')}."
        )

    # P5: include scan coverage warning in the business impact output
    coverage = risk.get("scan_coverage", {})
    coverage_banner = coverage.get("coverage_banner")

    return {
        "domain":                  domain,
        "overall_risk_score":      risk.get("risk_score", 0),
        "overall_severity":        risk.get("severity", "UNKNOWN"),
        "executive_summary":       _executive_summary(domain, risk, translated, attack_paths, coverage),
        "translated_findings":     translated,
        "top_attack_path":         top_path_exec,
        # P1 FIX: counts derived from ALL findings (including asset-level)
        "critical_findings_count": len(critical),
        "high_findings_count":     len(high),
        "medium_findings_count":   len(medium),
        "compliance_risks":        _aggregate_compliance(translated),
        "operational_impact":      _aggregate_operational(translated),
        "scan_coverage_warning":   coverage_banner,  # P5: surfaces disabled modules
        "asset_score_breakdown":   risk.get("asset_score_breakdown", []),
    }


def _executive_summary(domain, risk, translated, attack_paths, coverage=None) -> str:
    score    = risk.get("risk_score", 0)
    severity = risk.get("severity", "UNKNOWN")
    n_paths  = len(attack_paths)

    # P6 FIX: lead with the highest-severity ASSET-level finding
    # (findings from subdomains, not just root domain)
    top_finding_text = ""
    for t in translated:
        # asset-level = host differs from root domain OR category is Infrastructure/Attack Surface
        if t["severity"] in ("CRITICAL", "HIGH"):
            top_finding_text = f" Most urgent: {t['executive_summary']}"
            break

    critical_count = sum(1 for t in translated if t["severity"] == "CRITICAL")
    high_count     = sum(1 for t in translated if t["severity"] == "HIGH")
    total_serious  = critical_count + high_count

    # P5 FIX: append coverage warning if modules were disabled
    coverage_note = ""
    if coverage and coverage.get("disabled_count", 0) > 0:
        pct = coverage.get("coverage_percent", 100)
        disabled = coverage.get("disabled_count", 0)
        coverage_note = (
            f" Note: {disabled} intelligence module(s) were not run ({pct}% scan coverage) — "
            f"actual risk may be higher than reported."
        )

    return (
        f"{domain} has a risk score of {score}/100 ({severity}). "
        f"Our analysis identified {critical_count} critical and {high_count} high-severity findings "
        f"across all assets, with {n_paths} viable attack paths."
        f"{top_finding_text}"
        f" Immediate action is recommended on critical findings to reduce breach risk."
        f"{coverage_note}"
    )


def _estimate_effort(category: str, severity: str) -> str:
    if severity == "CRITICAL":
        return "Immediate (< 24 hours)"
    if severity == "HIGH":
        return "Urgent (< 1 week)"
    if category in ("SSL", "Security Headers", "CSP"):
        return "Low effort (configuration change)"
    return "Moderate (1-2 weeks)"


def _operational_risk(severity: str) -> str:
    return {
        "CRITICAL": "Service disruption or data breach imminent",
        "HIGH":     "Significant business risk if exploited",
        "MEDIUM":   "Moderate risk — may go unnoticed for extended periods",
        "LOW":      "Low operational impact",
    }.get(severity, "Unknown")


def _financial_risk(category: str, severity: str) -> str:
    if severity == "CRITICAL":
        return "Potential breach costs: regulatory fines + incident response + reputation damage"
    if category == "Email Security":
        return "BEC/phishing risk: direct financial fraud possible"
    if severity == "HIGH":
        return "Moderate financial exposure if exploited"
    return "Minimal direct financial risk"


def _aggregate_compliance(translated: list) -> list:
    seen, result = set(), []
    for t in translated:
        for c in t.get("compliance_risk", []):
            if c not in seen:
                result.append(c)
                seen.add(c)
    return result


def _aggregate_operational(translated: list) -> list:
    return list({t["operational_risk"] for t in translated if t.get("operational_risk")})
