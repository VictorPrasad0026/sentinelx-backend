"""
SentinelX V5 — Historical Scan Comparison Engine

Compares current scan against all previous snapshots.
Tracks:
  - Risk score trend (per-scan history)
  - New / removed / changed assets
  - New / resolved findings
  - Certificate changes (issuer, expiry, fingerprint)
  - Technology stack changes
  - Port changes (opened / closed)
  - WHOIS changes (registrar, expiry, nameservers)
  - IP address changes (infrastructure moves)
"""

import os
import json
from datetime import datetime, timezone
from collections import defaultdict


SNAPSHOT_DIR = "snapshots"


def _load_all_snapshots(domain: str) -> list:
    safe = domain.replace(".", "_")
    d = os.path.join(SNAPSHOT_DIR, safe)
    if not os.path.exists(d):
        return []
    snaps = []
    for fname in sorted(os.listdir(d)):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(d, fname), encoding="utf-8") as f:
                snaps.append({"file": fname, "data": json.load(f)})
        except Exception:
            pass
    return snaps


def _extract_asset_map(snap_data: dict) -> dict:
    """Build {host: {ports, techs, ip, ssl_fp}} from a snapshot."""
    assets = {}
    for a in snap_data.get("subdomain_assets", {}).get("assets", []):
        host = a.get("host", "")
        ports = sorted([p["port"] for p in a.get("infrastructure", {})
                        .get("ports", {}).get("ports", []) if p.get("state") == "OPEN"])
        techs = sorted([t["name"] if isinstance(t, dict) else t
                        for t in a.get("http", {}).get("technologies", [])])
        ip = a.get("infrastructure", {}).get("ip")
        ssl_fp = a.get("ssl", {}).get("fingerprint_sha256")
        assets[host] = {"ports": ports, "techs": techs, "ip": ip, "ssl_fp": ssl_fp}
    return assets


def compare_scans(domain: str, current_profile: dict) -> dict:
    snapshots = _load_all_snapshots(domain)

    if len(snapshots) < 1:
        return {
            "status": "FIRST_SCAN",
            "message": "No previous snapshots to compare against.",
            "scan_count": 0,
        }

    # Risk score history
    risk_history = []
    for s in snapshots:
        ts = s["file"].replace(".json", "")
        score = s["data"].get("risk_assessment", {}).get("risk_score", 0)
        risk_history.append({"timestamp": ts, "risk_score": score})

    current_score = current_profile.get("risk_assessment", {}).get("risk_score", 0)
    risk_history.append({
        "timestamp": datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S"),
        "risk_score": current_score,
    })

    # Compare vs most recent previous
    prev_data = snapshots[-1]["data"]
    prev_assets = _extract_asset_map(prev_data)
    curr_assets = _extract_asset_map(current_profile)

    prev_hosts = set(prev_assets)
    curr_hosts = set(curr_assets)

    new_assets     = sorted(curr_hosts - prev_hosts)
    removed_assets = sorted(prev_hosts - curr_hosts)

    changed_assets = []
    for host in curr_hosts & prev_hosts:
        p, c = prev_assets[host], curr_assets[host]
        changes = {}
        # Port changes
        added_ports   = sorted(set(c["ports"]) - set(p["ports"]))
        removed_ports = sorted(set(p["ports"]) - set(c["ports"]))
        if added_ports:   changes["ports_opened"] = added_ports
        if removed_ports: changes["ports_closed"]  = removed_ports
        # Tech changes
        added_tech   = sorted(set(c["techs"]) - set(p["techs"]))
        removed_tech = sorted(set(p["techs"]) - set(c["techs"]))
        if added_tech:   changes["technology_added"]   = added_tech
        if removed_tech: changes["technology_removed"] = removed_tech
        # IP change
        if c["ip"] != p["ip"] and p["ip"] and c["ip"]:
            changes["ip_changed"] = {"from": p["ip"], "to": c["ip"]}
        # Cert change
        if c["ssl_fp"] and p["ssl_fp"] and c["ssl_fp"] != p["ssl_fp"]:
            changes["certificate_rotated"] = True
        if changes:
            changed_assets.append({"host": host, "changes": changes})

    # Findings diff
    def finding_keys(profile):
        return {f"{f.get('category','?')}:{f.get('issue','?')}"
                for f in profile.get("risk_assessment", {}).get("findings", [])}

    prev_findings = finding_keys(prev_data)
    curr_findings = finding_keys(current_profile)
    new_findings      = sorted(curr_findings - prev_findings)
    resolved_findings = sorted(prev_findings - curr_findings)

    # WHOIS diff
    whois_changes = {}
    prev_whois = prev_data.get("domain_intelligence", {}).get("whois", {})
    curr_whois = current_profile.get("domain_intelligence", {}).get("whois", {})
    for key in ("registrar", "expires", "organization"):
        if prev_whois.get(key) != curr_whois.get(key):
            whois_changes[key] = {"from": prev_whois.get(key), "to": curr_whois.get(key)}

    prev_ns = set(prev_data.get("domain_intelligence", {}).get("nameservers", []))
    curr_ns = set(current_profile.get("domain_intelligence", {}).get("nameservers", []))
    if prev_ns != curr_ns:
        whois_changes["nameservers"] = {
            "added":   sorted(curr_ns - prev_ns),
            "removed": sorted(prev_ns - curr_ns),
        }

    # Risk delta
    prev_score  = prev_data.get("risk_assessment", {}).get("risk_score", 0)
    risk_delta  = current_score - prev_score
    risk_trend  = "INCREASING" if risk_delta > 0 else "DECREASING" if risk_delta < 0 else "STABLE"

    # Trend across all scans
    scores = [s["risk_score"] for s in risk_history]
    if len(scores) >= 3:
        recent_avg = sum(scores[-3:]) / 3
        older_avg  = sum(scores[:-3]) / max(len(scores[:-3]), 1)
        long_trend = "WORSENING" if recent_avg > older_avg + 3 else \
                     "IMPROVING" if recent_avg < older_avg - 3 else "STABLE"
    else:
        long_trend = "INSUFFICIENT_DATA"

    return {
        "status":           "COMPARISON_COMPLETE",
        "scan_count":       len(snapshots) + 1,
        "previous_scan":    snapshots[-1]["file"].replace(".json", ""),
        "risk_score_delta": risk_delta,
        "risk_trend":       risk_trend,
        "long_term_trend":  long_trend,
        "risk_history":     risk_history,
        "new_assets":       new_assets,
        "removed_assets":   removed_assets,
        "changed_assets":   changed_assets,
        "new_findings":     new_findings,
        "resolved_findings": resolved_findings,
        "whois_changes":    whois_changes,
        "summary": (
            f"Risk {risk_trend} by {abs(risk_delta)} points. "
            f"{len(new_assets)} new assets. "
            f"{len(removed_assets)} removed. "
            f"{len(changed_assets)} changed. "
            f"{len(new_findings)} new findings, {len(resolved_findings)} resolved."
        ),
    }
