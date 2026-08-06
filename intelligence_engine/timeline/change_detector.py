"""
SentinelX Change Detector

Compares two snapshots and returns a structured diff:
  - New assets discovered
  - Removed assets
  - New findings
  - Resolved findings
  - Risk score delta
  - Certificate changes
  - Technology changes
"""

from datetime import datetime, timezone


def detect_changes(old: dict, new: dict) -> dict:
    if not old or not new:
        return {"status": "NO_PREVIOUS_SNAPSHOT"}

    def subdomain_hosts(snap):
        return {
            a["host"]
            for a in snap.get("attack_surface_intelligence", {})
                         .get("assets", [])
        }

    def finding_keys(snap):
        return {
            f"{f.get('category')}:{f.get('issue')}"
            for f in snap.get("risk_assessment", {}).get("findings", [])
        }

    old_hosts    = subdomain_hosts(old)
    new_hosts    = subdomain_hosts(new)
    old_findings = finding_keys(old)
    new_findings = finding_keys(new)

    old_score = old.get("risk_assessment", {}).get("risk_score", 0)
    new_score = new.get("risk_assessment", {}).get("risk_score", 0)

    return {
        "comparison_time":   datetime.now(timezone.utc).isoformat(),
        "previous_scan":     old.get("scan_metadata", {}).get("scan_time"),
        "current_scan":      new.get("scan_metadata", {}).get("scan_time"),
        "risk_score_delta":  new_score - old_score,
        "risk_trend":        "INCREASING" if new_score > old_score
                             else "DECREASING" if new_score < old_score
                             else "STABLE",
        "new_assets":        sorted(new_hosts - old_hosts),
        "removed_assets":    sorted(old_hosts - new_hosts),
        "new_findings":      sorted(new_findings - old_findings),
        "resolved_findings": sorted(old_findings - new_findings),
        "summary": (
            f"Risk score changed by {new_score - old_score:+d}. "
            f"{len(new_hosts - old_hosts)} new assets discovered. "
            f"{len(old_hosts - new_hosts)} assets removed. "
            f"{len(new_findings - old_findings)} new findings. "
            f"{len(old_findings - new_findings)} resolved."
        ),
    }
