"""
SentinelX Business Impact Engine

Translates technical findings into executive language.
No technical jargon. Maps findings to operational/financial/compliance impact.
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


def translate_finding(finding: dict, asset: str) -> dict:
    category = finding.get("category", "default")
    issue    = finding.get("issue", "Unknown issue")
    severity = finding.get("severity", "MEDIUM")
    rec      = finding.get("recommendation", "Review and remediate")

    template = CATEGORY_TEMPLATES.get(category, CATEGORY_TEMPLATES["default"])
    exec_text = template.format(
        asset=asset,
        issue=issue.lower(),
        severity=SEVERITY_TO_EXEC.get(severity, severity.lower()),
    )

    return {
        "technical_finding": issue,
        "executive_summary": exec_text,
        "category":          category,
        "severity":          severity,
        "compliance_risk":   COMPLIANCE_MAP.get(category, []),
        "recommendation":    rec,
        "estimated_effort":  _estimate_effort(category, severity),
        "operational_risk":  _operational_risk(severity),
        "financial_risk":    _financial_risk(category, severity),
    }


def generate_business_impact(profile: dict, attack_paths: list) -> dict:
    risk = profile.get("risk_assessment", {})
    findings = risk.get("findings", [])
    domain = profile.get("asset", "unknown")

    translated = [translate_finding(f, domain) for f in findings]

    # Group by severity
    critical = [t for t in translated if t["severity"] == "CRITICAL"]
    high     = [t for t in translated if t["severity"] == "HIGH"]
    medium   = [t for t in translated if t["severity"] == "MEDIUM"]

    # Top attack path in exec language
    top_path_exec = None
    if attack_paths:
        top = attack_paths[0]
        top_path_exec = (
            f"The most likely attack scenario starts at {top['entry_point']} "
            f"via {top['service']} (port {top['port']}). "
            f"Business impact: {top['business_impact']}."
        )

    return {
        "domain":                   domain,
        "overall_risk_score":       risk.get("risk_score", 0),
        "overall_severity":         risk.get("severity", "UNKNOWN"),
        "executive_summary":        _executive_summary(domain, risk, translated, attack_paths),
        "translated_findings":      translated,
        "top_attack_path":          top_path_exec,
        "critical_findings_count":  len(critical),
        "high_findings_count":      len(high),
        "medium_findings_count":    len(medium),
        "compliance_risks":         _aggregate_compliance(translated),
        "operational_impact":       _aggregate_operational(translated),
    }


def _executive_summary(domain, risk, translated, attack_paths) -> str:
    score    = risk.get("risk_score", 0)
    severity = risk.get("severity", "UNKNOWN")
    n_paths  = len(attack_paths)
    n_critical = sum(1 for t in translated if t["severity"] in ("CRITICAL", "HIGH"))

    return (
        f"{domain} has a security risk score of {score}/100 ({severity}). "
        f"Our analysis identified {n_critical} high-severity findings and "
        f"{n_paths} potential attack paths. "
        f"Immediate action is recommended on critical and high severity items "
        f"to reduce the risk of unauthorized access to business systems."
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
    seen = set()
    result = []
    for t in translated:
        for c in t.get("compliance_risk", []):
            if c not in seen:
                result.append(c)
                seen.add(c)
    return result


def _aggregate_operational(translated: list) -> list:
    return list({t["operational_risk"] for t in translated if t.get("operational_risk")})
