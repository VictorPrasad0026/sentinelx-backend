"""
SentinelX Crown Jewel Identifier

Identifies the most business-critical assets from the attack surface.
These are assets that if compromised would have maximum blast radius.
"""


def identify_crown_jewels(attack_surface: dict) -> dict:
    assets = attack_surface.get("assets", [])

    crown_jewels = [a for a in assets if a["criticality"]["is_crown_jewel"]]
    high = [a for a in assets if a["criticality"]["criticality_label"] == "HIGH"
            and not a["criticality"]["is_crown_jewel"]]

    return {
        "crown_jewels":       crown_jewels,
        "high_value_assets":  high,
        "crown_jewel_count":  len(crown_jewels),
        "summary": (
            f"Identified {len(crown_jewels)} crown jewel assets that require "
            f"priority protection and {len(high)} high-value assets."
        ),
    }
