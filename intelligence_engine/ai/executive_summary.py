"""
SentinelX Executive Summary Generator

Uses only graph-derived evidence to generate a plain-language
executive report. Never asks the LLM to invent facts.
"""

from intelligence_engine.ai.llm_client import complete

SYSTEM = """
You are a cybersecurity advisor writing for a non-technical executive audience.
You will receive structured security findings from an automated scan.
Your job:
1. Summarise the security posture in 3-5 plain sentences.
2. Highlight the top 3 risks in plain business language (no CVE IDs, no port numbers).
3. State the single most important immediate action.
4. Keep it under 200 words.
5. Never mention tools, scanners, or CVEs. Focus on business impact.
IMPORTANT: Only use the data provided. Do not invent risks or remediation steps.
""".strip()


def generate_executive_summary(business_impact: dict) -> str:
    context = {
        "domain":         business_impact.get("domain"),
        "risk_score":     business_impact.get("overall_risk_score"),
        "severity":       business_impact.get("overall_severity"),
        "top_findings":   business_impact.get("translated_findings", [])[:5],
        "top_attack_path": business_impact.get("top_attack_path"),
        "compliance":     business_impact.get("compliance_risks", []),
    }
    return complete(SYSTEM, f"Security data:\n{context}", max_tokens=400)
