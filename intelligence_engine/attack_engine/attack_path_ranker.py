"""
SentinelX Attack Path Ranker

Ranks paths by: likelihood × business_impact × confidence.
Separate from building paths — pure scoring logic.
"""

IMPACT_WEIGHT = {
    "Data breach":     1.5,
    "Container":       1.4,
    "Windows lateral": 1.3,
    "Admin panel":     1.2,
    "API":             1.1,
    "default":         1.0,
}

CONFIDENCE_WEIGHT = {
    "HIGH":   1.0,
    "MEDIUM": 0.75,
    "LOW":    0.5,
}


def rank_paths(paths: list[dict]) -> list[dict]:
    for path in paths:
        impact_key = "default"
        impact_str = path.get("business_impact", "")
        for key in IMPACT_WEIGHT:
            if key.lower() in impact_str.lower():
                impact_key = key
                break

        cw = CONFIDENCE_WEIGHT.get(path.get("confidence", "LOW"), 0.5)
        iw = IMPACT_WEIGHT.get(impact_key, 1.0)
        raw = path.get("likelihood", 0) * cw * iw
        path["composite_score"] = round(min(raw, 100), 1)

    paths.sort(key=lambda x: x["composite_score"], reverse=True)

    for i, p in enumerate(paths):
        p["rank"] = i + 1

    return paths
