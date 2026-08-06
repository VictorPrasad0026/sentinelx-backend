"""
SentinelX Security Copilot

Answers natural-language security questions about a domain
using ONLY graph evidence injected into each prompt.

No hallucination: every answer cites the data it was given.
"""

from intelligence_engine.ai.llm_client import complete
import json

SYSTEM = """
You are SentinelX Security Copilot — an AI assistant that answers security questions
about a specific domain using ONLY the scan data provided to you.

Rules:
1. NEVER invent risks, IPs, subdomains, technologies, or CVEs.
2. If the data does not contain the answer, say "Not found in current scan data."
3. Always cite which part of the data your answer comes from.
4. Answer in plain English. Avoid jargon unless the user asks for technical detail.
5. For CEO / executive questions, focus on business impact, not technical details.
""".strip()

PREDEFINED_QUERIES = {
    "most_critical_asset":   "What is my most critical asset?",
    "highest_attack_path":   "Which attack path has the highest probability?",
    "top_remediation":       "Which remediation reduces the most risk?",
    "internet_facing_dbs":   "Show every internet-facing database.",
    "changes_summary":       "What changed since the last scan?",
    "ceo_summary":           "Explain the security posture to a CEO.",
}


def ask(question: str, intelligence_report: dict) -> str:
    """
    Ask any question. The full intelligence report is injected as context.
    """
    # Trim to essentials to keep prompt size manageable
    context = {
        "domain":           intelligence_report.get("domain"),
        "risk_score":       intelligence_report.get("risk_assessment", {}).get("risk_score"),
        "severity":         intelligence_report.get("risk_assessment", {}).get("severity"),
        "crown_jewels":     [
            a["host"]
            for a in intelligence_report.get("attack_surface_intelligence", {})
                                         .get("crown_jewels", [])
        ],
        "top_attack_paths": intelligence_report.get("attack_paths", [])[:3],
        "top_findings":     intelligence_report.get("risk_assessment", {})
                                               .get("findings", [])[:10],
        "changes":          intelligence_report.get("changes", {}),
        "remediation_plan": intelligence_report.get("remediation_plan", {})
                                               .get("all_remediations", [])[:5],
    }

    prompt = (
        f"Scan data for {context['domain']}:\n"
        f"{json.dumps(context, indent=2, default=str)}\n\n"
        f"Question: {question}"
    )
    return complete(SYSTEM, prompt, max_tokens=600)


def run_predefined(query_key: str, intelligence_report: dict) -> str:
    question = PREDEFINED_QUERIES.get(query_key)
    if not question:
        return f"Unknown query key: {query_key}. Available: {list(PREDEFINED_QUERIES)}"
    return ask(question, intelligence_report)
