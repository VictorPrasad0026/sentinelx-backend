"""
SentinelX Fix Prioritizer

Ranks remediation actions by which fix breaks the most attack paths
and reduces the most risk with the least effort.
"""

from typing import List, Dict, Any


EFFORT_MAP = {
    "Missing HSTS": {"effort": "LOW", "hours": 1, "complexity": "LOW"},
    "Missing Content Security Policy": {"effort": "MEDIUM", "hours": 4, "complexity": "MEDIUM"},
    "Missing SPF": {"effort": "LOW", "hours": 1, "complexity": "LOW"},
    "Missing DMARC": {"effort": "LOW", "hours": 2, "complexity": "LOW"},
    "DKIM": {"effort": "MEDIUM", "hours": 4, "complexity": "MEDIUM"},
    "SSL": {"effort": "LOW", "hours": 2, "complexity": "LOW"},
    "TLS": {"effort": "MEDIUM", "hours": 4, "complexity": "MEDIUM"},
    "RDP": {"effort": "LOW", "hours": 1, "complexity": "LOW"},
    "database": {"effort": "MEDIUM", "hours": 8, "complexity": "MEDIUM"},
    "docker": {"effort": "HIGH", "hours": 16, "complexity": "HIGH"},
    "kube": {"effort": "HIGH", "hours": 24, "complexity": "HIGH"},
    "WAF": {"effort": "MEDIUM", "hours": 8, "complexity": "MEDIUM"},
    "default": {"effort": "MEDIUM", "hours": 8, "complexity": "MEDIUM"}
}

SEVERITY_RISK_REDUCTION = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5, "INFO": 1}


class FixPrioritizer:

    def prioritize(self, findings: List[Dict]) -> List[Dict]:
        prioritized = []
        for f in findings:
            effort = self._get_effort(f.get("issue", ""))
            risk_reduction = SEVERITY_RISK_REDUCTION.get(f.get("severity", "INFO"), 1)
            roi = risk_reduction / max(effort["hours"], 1)
            prioritized.append({
                "finding": f.get("issue"),
                "severity": f.get("severity"),
                "recommendation": f.get("recommendation", "Review and remediate"),
                "effort": effort["effort"],
                "estimated_hours": effort["hours"],
                "implementation_complexity": effort["complexity"],
                "risk_reduction": risk_reduction,
                "roi_score": round(roi, 2)
            })
        return sorted(prioritized, key=lambda x: x["roi_score"], reverse=True)

    def _get_effort(self, issue: str) -> Dict:
        issue_lower = issue.lower()
        for keyword, effort in EFFORT_MAP.items():
            if keyword.lower() in issue_lower:
                return effort
        return EFFORT_MAP["default"]
