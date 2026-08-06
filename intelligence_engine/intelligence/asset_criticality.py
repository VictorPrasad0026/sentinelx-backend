"""
SentinelX Asset Criticality Engine

Scores every asset 0-100 for business criticality.
Factors: asset type, exposure, connectivity, blast radius.
"""

from intelligence_engine.intelligence.asset_classifier import classify_asset

CRITICALITY_WEIGHTS = {
    "Admin Panel":             30,
    "Authentication System":   35,
    "Database":                40,
    "Database (Port)":         35,
    "Admin Interface (Port)":  25,
    "Development/Staging":     15,
    "Backup System":           20,
    "Web Asset":               10,
}

RISK_SEVERITY_SCORE = {
    "CRITICAL": 30,
    "HIGH":     20,
    "MEDIUM":   10,
    "LOW":       5,
    "UNKNOWN":   0,
}


def score_asset(host: str, open_ports: list, technologies: list,
                risk_severity: str, finding_count: int,
                subdomain_count: int = 0) -> dict:

    classification = classify_asset(host, open_ports, technologies)
    score = 0

    # Asset type base score
    for asset_type in classification["asset_types"]:
        score += CRITICALITY_WEIGHTS.get(asset_type, 10)

    # Risk severity
    score += RISK_SEVERITY_SCORE.get(risk_severity, 0)

    # Internet exposure (more open ports = higher criticality)
    score += min(len(open_ports) * 5, 20)

    # Sensitive keyword bonus
    score += len(classification["sensitive_keywords"]) * 5

    # Finding density
    score += min(finding_count * 2, 15)

    score = min(score, 100)

    if score >= 75:
        label = "CROWN_JEWEL"
    elif score >= 50:
        label = "HIGH"
    elif score >= 25:
        label = "MEDIUM"
    else:
        label = "LOW"

    return {
        "host":            host,
        "criticality_score": score,
        "criticality_label": label,
        "classification":  classification,
        "is_crown_jewel":  label == "CROWN_JEWEL",
    }
