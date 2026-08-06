"""
SentinelX Report Explainer

Explains specific findings or attack paths in plain language.
Grounded in the provided data — no invented context.
"""

from intelligence_engine.ai.llm_client import complete
import json

FINDING_SYSTEM = """
You are a security expert translating a technical finding for a developer or IT admin.
Use the exact finding data provided. Explain:
1. What the issue is (1 sentence)
2. Why it matters (1-2 sentences)
3. How to fix it (2-3 concrete steps)
Keep it under 150 words. Be specific, actionable, and accurate.
""".strip()

PATH_SYSTEM = """
You are a security expert explaining an attack scenario to a security team.
Use only the attack path data provided. Explain:
1. How an attacker would exploit this in plain English
2. What they could achieve
3. What single action would block this path
Keep it under 150 words. Ground everything in the provided evidence.
""".strip()


def explain_finding(finding: dict) -> str:
    return complete(FINDING_SYSTEM, f"Finding:\n{json.dumps(finding, indent=2)}", max_tokens=300)


def explain_attack_path(path: dict) -> str:
    return complete(PATH_SYSTEM, f"Attack path:\n{json.dumps(path, indent=2, default=str)}", max_tokens=300)
