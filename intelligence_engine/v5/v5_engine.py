"""
SentinelX V5 Intelligence Engine

17 new capabilities on top of V4:

  1.  Historical scan comparison          historical_comparison.py
  2.  CVE-enriched attack path generation attack_path_generator.py
  3.  CVE mapping + EPSS + KEV            vuln_prioritization.py
  4.  TLS configuration grading (A+-F)    tls_grading.py
  5.  Certificate transparency timeline   tls_grading.fetch_ct_timeline
  6.  Login page identification           login_detection.py
  7.  Default credential detection        login_detection.py (risk only)
  8.  JavaScript endpoint discovery       (V4 js_intelligence, enhanced)
  9.  Secrets exposure checks             secrets_exposure.py
  10. Public bucket detection             secrets_exposure.check_public_buckets
  11. GitHub leak correlation             secrets_exposure.check_github_leaks
  12. WHOIS change tracking               historical_comparison (whois_changes)
  13. Passive DNS history                 passive_dns.py
  14. Screenshot capture                  screenshot_capture.py
  15. Risk trends over time               historical_comparison (risk_history)
  16. Internet-wide asset correlation     (V4 asset_correlation, enhanced)
  17. Vulnerability prioritization        vuln_prioritization.py

Entry: run_v5(profile, v4_report, options) -> v5_report
"""

import time
import os
import json
from datetime import datetime, timezone

from intelligence_engine.v5.historical_comparison import compare_scans
from intelligence_engine.v5.tls_grading import grade_all_assets, fetch_ct_timeline
from intelligence_engine.v5.login_detection import scan_all_assets as scan_logins
from intelligence_engine.v5.secrets_exposure import (
    scan_secrets, check_public_buckets, check_github_leaks
)
from intelligence_engine.v5.passive_dns import get_passive_dns_history
from intelligence_engine.v5.screenshot_capture import capture_all
from intelligence_engine.v5.vuln_prioritization import run_vuln_prioritization
from intelligence_engine.v5.attack_path_generator import generate_attack_paths


def _step(label: str, func, *args, **kwargs):
    try:
        t = time.time()
        result = func(*args, **kwargs)
        elapsed = round(time.time() - t, 2)
        print(f"  [✓] {label} ({elapsed}s)")
        return result
    except Exception as e:
        print(f"  [!] {label} failed: {e}")
        import traceback
        traceback.print_exc()
        return {}


def run_v5(profile: dict,
           v4_report: dict,
           enable_screenshots:   bool = False,
           enable_passive_dns:   bool = True,
           enable_vuln_intel:    bool = True,
           enable_login_scan:    bool = True,
           enable_secrets_scan:  bool = True,
           enable_github:        bool = False,
           enable_ct_timeline:   bool = True,
           max_assets:           int  = 8) -> dict:

    domain = profile.get("asset", "unknown")
    start  = time.time()

    print(f"\n{'='*62}")
    print(f"  SentinelX V5 Intelligence Engine")
    print(f"  Domain: {domain}")
    print(f"{'='*62}\n")

    report = {
        "domain":       domain,
        "engine":       "SentinelX V5 Intelligence Engine",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    # All assets for scanning
    raw_assets = profile.get("subdomain_assets", {}).get("assets", [])
    top_risk_assets = sorted(raw_assets, key=lambda a: a.get("risk", {}).get("score", 0), reverse=True)

    # ── 1. Historical comparison ────────────────────────────────
    print("[1/12] Historical Scan Comparison")
    history = _step("Compare against all previous snapshots", compare_scans, domain, profile)
    report["historical_comparison"] = history

    # ── 2. TLS Grading ─────────────────────────────────────────
    print("\n[2/12] TLS Configuration Grading")
    tls_grades = _step("Grade A+ to F for all assets", grade_all_assets, profile)
    report["tls_grades"] = tls_grades

    # ── 3. Certificate Transparency Timeline ───────────────────
    if enable_ct_timeline:
        print("\n[3/12] Certificate Transparency Timeline")
        ct_timeline = _step("Fetch CT log history from crt.sh", fetch_ct_timeline, domain)
        report["ct_timeline"] = ct_timeline
    else:
        report["ct_timeline"] = {"note": "Disabled"}

    # ── 4. Vulnerability Prioritization ────────────────────────
    if enable_vuln_intel:
        print("\n[4/12] Vulnerability Prioritization (NVD + KEV + EPSS)")
        vuln_report = _step("CVE lookup + EPSS + CISA KEV ranking", run_vuln_prioritization, profile)
        report["vulnerability_prioritization"] = vuln_report
    else:
        vuln_report = {}
        report["vulnerability_prioritization"] = {"note": "Disabled — pass enable_vuln_intel=True"}

    # ── 5. Login Page + Default Credentials ───────────────────
    if enable_login_scan:
        print("\n[5/12] Login Page + Default Credential Detection")
        login_results = _step(f"Scan {min(max_assets, len(top_risk_assets))} assets", scan_logins, top_risk_assets, max_assets)
        report["login_detection"] = login_results
    else:
        login_results = []
        report["login_detection"] = []

    # ── 6. Secrets Exposure ────────────────────────────────────
    if enable_secrets_scan:
        print("\n[6/12] Secrets + Sensitive File Exposure")
        secrets_results = []
        for asset in top_risk_assets[:min(max_assets, 5)]:
            host = asset.get("host", "")
            print(f"    → Scanning {host}...")
            r = scan_secrets(host)
            secrets_results.append(r)
        report["secrets_exposure"] = secrets_results

        # Public bucket check
        print("\n[7/12] Public Cloud Bucket Detection")
        buckets = _step("Check domain-named buckets (S3/GCS/Azure)", check_public_buckets, domain)
        report["public_buckets"] = buckets if isinstance(buckets, list) else []
    else:
        secrets_results = []
        report["secrets_exposure"] = []
        report["public_buckets"] = []

    # ── 7. GitHub Leak Correlation ────────────────────────────
    if enable_github:
        print("\n[8/12] GitHub Leak Correlation")
        github = _step("Search public GitHub for domain credential leaks", check_github_leaks, domain)
        report["github_leaks"] = github if isinstance(github, list) else []
    else:
        report["github_leaks"] = [{"note": "Disabled — pass enable_github=True to enable (rate limited)"}]

    # ── 8. Passive DNS History ────────────────────────────────
    if enable_passive_dns:
        print("\n[9/12] Passive DNS History")
        passive = _step("Query HackerTarget + CIRCL + CT logs + RapidDNS", get_passive_dns_history, domain)
        report["passive_dns"] = passive
    else:
        report["passive_dns"] = {"note": "Disabled"}

    # ── 9. Screenshots ────────────────────────────────────────
    if enable_screenshots:
        print("\n[10/12] Screenshot Capture")
        screenshots = _step(f"Capture {min(max_assets, len(top_risk_assets))} assets", capture_all, top_risk_assets, max_assets)
        report["screenshots"] = screenshots
    else:
        report["screenshots"] = [{"note": "Disabled — pass enable_screenshots=True (requires: pip install playwright && playwright install chromium)"}]

    # ── 10. CVE-enriched Attack Paths ────────────────────────
    print("\n[11/12] CVE-Enriched Attack Path Generation")
    attack_paths = _step("Merge V4 chains + CVEs + logins + secrets",
                          generate_attack_paths, v4_report, vuln_report,
                          tls_grades, login_results, secrets_results)
    report["enriched_attack_paths"] = attack_paths

    # ── 11. Risk trends ──────────────────────────────────────
    print("\n[12/12] Risk Trend Analysis")
    hist = report.get("historical_comparison", {})
    risk_hist = hist.get("risk_history", [])
    current_score = profile.get("risk_assessment", {}).get("risk_score", 0)

    if len(risk_hist) >= 2:
        scores = [h["risk_score"] for h in risk_hist]
        trend_7d = scores[-1] - scores[-2] if len(scores) >= 2 else 0
        trend_all = scores[-1] - scores[0] if len(scores) >= 2 else 0
    else:
        trend_7d = 0
        trend_all = 0

    report["risk_trends"] = {
        "current_score":  current_score,
        "score_history":  risk_hist,
        "trend_last":     trend_7d,
        "trend_overall":  trend_all,
        "direction":      "INCREASING" if trend_all > 0 else "DECREASING" if trend_all < 0 else "STABLE",
        "scan_count":     hist.get("scan_count", 1),
    }

    # ── Aggregate all V5 findings ──────────────────────────────
    all_findings = []
    for key in ("login_detection", "secrets_exposure"):
        items = report.get(key, [])
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    all_findings.extend(item.get("findings", []))
    for key in ("vulnerability_prioritization",):
        item = report.get(key, {})
        if isinstance(item, dict):
            all_findings.extend(item.get("findings", []))
    for item in report.get("passive_dns", {}).get("findings", []):
        all_findings.append(item)

    report["v5_findings"] = all_findings
    report["v5_duration_seconds"] = round(time.time() - start, 2)

    _print_summary(report)
    return report


def _print_summary(r: dict):
    ap  = r.get("enriched_attack_paths", {})
    tls = r.get("tls_grades", {})
    vp  = r.get("vulnerability_prioritization", {})
    hist = r.get("historical_comparison", {})

    print(f"\n{'='*62}")
    print("  SentinelX V5 Complete")
    print(f"{'='*62}")
    print(f"  Enriched Attack Paths : {ap.get('total_paths', 0)}")
    print(f"  Critical Paths        : {ap.get('critical_paths', 0)}")
    print(f"  KEV-matched Paths     : {ap.get('kev_paths', 0)}")
    print(f"  TLS Failed Assets     : {len(tls.get('failed_assets', []))}")
    print(f"  CVEs found            : {vp.get('total_cves', 0) if isinstance(vp, dict) else 0}")
    print(f"  KEV matches           : {vp.get('kev_matched', 0) if isinstance(vp, dict) else 0}")
    print(f"  Historical scans      : {hist.get('scan_count', 1)}")
    print(f"  Risk trend            : {r.get('risk_trends', {}).get('direction', 'N/A')}")
    print(f"  V5 Findings           : {len(r.get('v5_findings', []))}")
    print(f"  Duration              : {r.get('v5_duration_seconds')}s")
    print(f"{'='*62}\n")


def save_v5_report(report: dict) -> str:
    os.makedirs("reports", exist_ok=True)
    domain = report.get("domain", "unknown")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"reports/{domain}_v5_{ts}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, default=str)
    print(f"[+] V5 report saved: {path}")
    return path
