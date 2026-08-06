"""
SentinelX Attack Path Validator

Validates every attack path before ranking:
  - Required fields present
  - Likelihood is a number 0-100
  - At least one step exists
  - entry_point is a non-empty string

Returns only valid paths; logs invalid ones.
"""

REQUIRED_FIELDS = [
    "path_id", "entry_point", "service", "port",
    "steps", "likelihood", "confidence", "risk_level",
]


def validate_paths(paths: list) -> list:
    valid = []
    for path in paths:
        issues = _check(path)
        if issues:
            print(f"  [!] Invalid path {path.get('path_id')}: {issues}")
            continue
        valid.append(path)
    return valid


def _check(path: dict) -> list:
    issues = []
    for field in REQUIRED_FIELDS:
        if field not in path:
            issues.append(f"missing field: {field}")

    if not isinstance(path.get("likelihood"), (int, float)):
        issues.append("likelihood must be numeric")
    elif not (0 <= path["likelihood"] <= 100):
        issues.append("likelihood must be 0-100")

    if not path.get("steps"):
        issues.append("steps list is empty")

    if not path.get("entry_point", "").strip():
        issues.append("entry_point is empty")

    return issues
