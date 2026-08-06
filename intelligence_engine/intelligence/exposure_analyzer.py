"""
SentinelX Exposure Analyzer

Calculates internet exposure for each asset.
Separate from risk scoring — exposure = how reachable are you.
"""

HIGH_RISK_PORTS = {23, 3306, 5432, 6379, 27017, 9200, 2375, 445, 3389, 4444}
MEDIUM_RISK_PORTS = {21, 22, 25, 3389, 5900, 1433, 1521}


def analyze_exposure(host: str, open_ports: list, waf_detected: bool,
                     cdn_detected: bool, ssl_status: str) -> dict:

    score = 0
    factors = []

    critical_exposed = [p for p in open_ports if p in HIGH_RISK_PORTS]
    medium_exposed   = [p for p in open_ports if p in MEDIUM_RISK_PORTS]

    if critical_exposed:
        score += len(critical_exposed) * 25
        factors.append(f"Critical ports exposed: {critical_exposed}")

    if medium_exposed:
        score += len(medium_exposed) * 10
        factors.append(f"Sensitive ports exposed: {medium_exposed}")

    # Total open ports
    score += min(len(open_ports) * 2, 20)

    if not waf_detected:
        score += 10
        factors.append("No WAF protection")

    if not cdn_detected:
        score += 5
        factors.append("No CDN protection")

    if ssl_status not in ("VALID",):
        score += 15
        factors.append(f"SSL issue: {ssl_status}")

    score = min(score, 100)

    if score >= 70:
        level = "CRITICAL"
    elif score >= 40:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "host":             host,
        "exposure_score":   score,
        "exposure_level":   level,
        "critical_ports":   critical_exposed,
        "factors":          factors,
        "direct_internet":  len(open_ports) > 0,
    }
