"""
SentinelX Remediation Engine

Determines WHICH fixes break the most attack paths.
Outputs a prioritized remediation plan with:
  - Priority rank
  - Risk reduction %
  - Affected assets
  - Implementation complexity
  - Estimated effort
"""

from collections import defaultdict

FIX_CATALOG = {
    "SSL": {
        "title":       "Renew or fix SSL/TLS certificate",
        "complexity":  "LOW",
        "effort":      "< 2 hours",
        "paths_broken_weight": 20,
    },
    "TLS": {
        "title":       "Upgrade TLS to 1.2/1.3 only",
        "complexity":  "LOW",
        "effort":      "1-2 hours (server config)",
        "paths_broken_weight": 15,
    },
    "Security Headers": {
        "title":       "Add missing HTTP security headers",
        "complexity":  "LOW",
        "effort":      "1-4 hours (web server / CDN config)",
        "paths_broken_weight": 8,
    },
    "CSP": {
        "title":       "Implement Content Security Policy",
        "complexity":  "MEDIUM",
        "effort":      "1-3 days (requires app-level analysis)",
        "paths_broken_weight": 10,
    },
    "Email Security": {
        "title":       "Harden email security (SPF/DKIM/DMARC)",
        "complexity":  "LOW",
        "effort":      "2-8 hours (DNS changes)",
        "paths_broken_weight": 15,
    },
    "Infrastructure": {
        "title":       "Restrict exposed services (firewall / VPN)",
        "complexity":  "MEDIUM",
        "effort":      "4-8 hours per service",
        "paths_broken_weight": 30,
    },
    "Attack Surface": {
        "title":       "Remove or secure sensitive subdomains",
        "complexity":  "HIGH",
        "effort":      "1-2 weeks (requires stakeholder review)",
        "paths_broken_weight": 25,
    },
    "WAF": {
        "title":       "Deploy Web Application Firewall",
        "complexity":  "MEDIUM",
        "effort":      "1-3 days (Cloudflare / AWS WAF / ModSecurity)",
        "paths_broken_weight": 20,
    },
}


def generate_remediation_plan(findings: list, attack_paths: list) -> dict:
    # Group findings by category
    by_category: dict[str, list] = defaultdict(list)
    for f in findings:
        cat = f.get("category", "Unknown")
        by_category[cat].append(f)

    # Count how many attack paths each category blocks
    paths_by_service: dict[str, int] = defaultdict(int)
    for path in attack_paths:
        paths_by_service[path.get("service", "Unknown")] += 1

    remediations = []

    for category, cat_findings in by_category.items():
        catalog_entry = FIX_CATALOG.get(category, {
            "title":       f"Remediate {category} findings",
            "complexity":  "MEDIUM",
            "effort":      "Varies",
            "paths_broken_weight": 5,
        })

        affected_assets = list({f.get("asset", "unknown") for f in cat_findings})
        max_severity = max(
            (f.get("severity", "LOW") for f in cat_findings),
            key=lambda s: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(s, 0),
            default="LOW",
        )
        total_score = sum(f.get("score", 0) for f in cat_findings)

        # Estimate paths broken
        paths_broken = catalog_entry["paths_broken_weight"]

        # Risk reduction % = proportion of total score this fix addresses
        total_all = sum(f.get("score", 0) for f in findings) or 1
        risk_reduction = round((total_score / total_all) * 100, 1)

        remediations.append({
            "category":        category,
            "title":           catalog_entry["title"],
            "findings_count":  len(cat_findings),
            "max_severity":    max_severity,
            "risk_reduction":  risk_reduction,
            "paths_broken":    paths_broken,
            "affected_assets": affected_assets,
            "complexity":      catalog_entry["complexity"],
            "effort":          catalog_entry["effort"],
            "priority_score":  _priority_score(max_severity, risk_reduction, paths_broken,
                                               catalog_entry["complexity"]),
        })

    remediations.sort(key=lambda x: x["priority_score"], reverse=True)
    for i, r in enumerate(remediations):
        r["priority_rank"] = i + 1

    return {
        "total_remediations": len(remediations),
        "quick_wins":  [r for r in remediations if r["complexity"] == "LOW"],
        "all_remediations": remediations,
        "summary": (
            f"{len(remediations)} remediation actions identified. "
            f"{sum(1 for r in remediations if r['complexity'] == 'LOW')} are quick wins "
            f"(low complexity). Start with Priority 1."
        ),
    }


def _priority_score(severity: str, risk_reduction: float,
                    paths_broken: int, complexity: str) -> float:
    sev_w = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 20, "LOW": 10}.get(severity, 10)
    comp_w = {"LOW": 1.5, "MEDIUM": 1.0, "HIGH": 0.7}.get(complexity, 1.0)
    return round((sev_w + risk_reduction + paths_broken) * comp_w, 1)
