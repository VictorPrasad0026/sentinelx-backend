"""
SentinelX Executive Summary Generator  v2
FIXED:
  P5 — Scan Coverage banner surfaced at top of every report
  P6 — Summary leads with highest-severity ASSET-level finding
"""

from intelligence_engine.ai.llm_client import complete

SYSTEM = """
You are a cybersecurity advisor writing for a non-technical executive audience.
You will receive structured security findings from an automated scan.

Your job:
1. Open with the single most dangerous finding — name the specific asset at risk and the business consequence.
2. Summarise the overall security posture in 2-3 plain sentences.
3. List the top 3 risks in plain business language (no CVE IDs, no port numbers, no tool names).
4. State the single most important immediate action.
5. If the scan had disabled modules, note that the real risk may be higher.
6. Keep it under 220 words.

IMPORTANT:
- Only use the data provided. Do not invent risks or remediation steps.
- Lead with asset-level findings (subdomains), not root-domain header findings.
- Never mention scanners, CVE IDs, port numbers, or tool names.
""".strip()


def generate_executive_summary(business_impact: dict) -> str:
    # P6 FIX: sort findings so asset-level CRITICAL/HIGH come first
    all_findings = business_impact.get("translated_findings", [])
    sorted_findings = sorted(
        all_findings,
        key=lambda f: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(f.get("severity", "LOW"), 3),
            # asset findings (source_host != root domain) float above root-domain findings
            0 if f.get("source_host", "") != business_impact.get("domain", "") else 1
        )
    )

    # P5 FIX: include scan coverage warning in context
    coverage_note = ""
    warning = business_impact.get("scan_coverage_warning")
    if warning:
        coverage_note = f"\n\nSCAN COVERAGE WARNING: {warning}"

    context = {
        "domain":            business_impact.get("domain"),
        "risk_score":        business_impact.get("overall_risk_score"),
        "severity":          business_impact.get("overall_severity"),
        # P6: asset-level critical findings first
        "top_findings":      sorted_findings[:6],
        "top_attack_path":   business_impact.get("top_attack_path"),
        "compliance":        business_impact.get("compliance_risks", []),
        "critical_count":    business_impact.get("critical_findings_count", 0),
        "high_count":        business_impact.get("high_findings_count", 0),
        "asset_breakdown":   business_impact.get("asset_score_breakdown", [])[:5],
    }

    prompt = f"Security data:\n{context}{coverage_note}"
    return complete(SYSTEM, prompt, max_tokens=450)
