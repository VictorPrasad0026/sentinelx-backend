"""
SentinelX AI Reasoning Engine

Builds evidence-grounded context from the graph and feeds it to the LLM.
NEVER hallucinates — only uses data extracted from the actual graph.
All reasoning is traceable to graph nodes/edges.
"""

from intelligence_engine.ai.llm_client import complete

SYSTEM_PROMPT = """You are SentinelX Security Copilot, an AI security analyst.

You ONLY answer based on the evidence provided in the [GRAPH DATA] section.
You NEVER invent vulnerabilities, assets, or findings that are not in the data.
If the data does not contain enough information to answer, say: "Not found in current scan data."

Your answers must be:
- Factual and evidence-based
- Professional and concise
- Useful to both technical teams and business executives
- Free of speculation

When referencing findings, always cite the finding name and severity.
""".strip()


def build_context(graph: dict, profile: dict) -> str:
    nodes = graph.get("nodes", [])
    risk  = profile.get("risk_assessment", {})
    surface = profile.get("attack_surface", {})
    domain  = profile.get("asset", "unknown")

    lines = [
        f"Domain: {domain}",
        f"Risk Score: {risk.get('risk_score')}/100  Severity: {risk.get('severity')}",
        f"Total Subdomains: {surface.get('total_subdomains')}",
        f"Resolved Assets: {surface.get('resolved_assets')}",
        f"Cloud Provider: {surface.get('cloud_provider')}",
        f"CDN Provider: {surface.get('cdn_provider')}",
        f"WAF Detected: {surface.get('waf_detected')}",
        "\nFINDINGS:",
    ]
    for f in risk.get("findings", [])[:20]:
        lines.append(f"  [{f.get('severity')}] {f.get('issue')} — {f.get('recommendation', '')}")

    lines.append("\nOPEN PORTS:")
    for p in surface.get("open_ports_summary", []):
        lines.append(f"  Port {p.get('port')} ({p.get('service')}) — Risk: {p.get('risk')}")

    lines.append("\nNODE SUMMARY:")
    type_counts: dict[str, int] = {}
    for n in nodes:
        t = n.get("node_type", "Unknown")
        type_counts[t] = type_counts.get(t, 0) + 1
    for t, count in type_counts.items():
        lines.append(f"  {t}: {count}")

    return "\n".join(lines)


def reason(question: str, graph: dict, profile: dict, max_tokens: int = 600) -> str:
    context = build_context(graph, profile)
    user_prompt = f"[GRAPH DATA]\n{context}\n\n[QUESTION]\n{question}"
    return complete(SYSTEM_PROMPT, user_prompt, max_tokens=max_tokens)
