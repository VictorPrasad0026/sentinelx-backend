"""
SentinelX V4 Intelligence Engine

Adds on top of V3:
  1. Asset Correlation        (findings grouped by asset, not category)
  2. Attack Graph Engine      (accurate evidence-only attack chains)
  3. Internet Exposure Score  (Wiz-style 0-100 per asset)
  4. Vulnerability Intelligence (NVD + CISA KEV + EPSS)
  5. API Discovery            (REST, GraphQL, Swagger probing)
  6. JavaScript Intelligence  (secrets, endpoints, internal IPs)

Entry: run_v4(profile, options) -> v4_report
"""

import time
import os
import json
from datetime import datetime, timezone

from intelligence_engine.v4.asset_correlation import correlate_assets
from intelligence_engine.v4.exposure_score import score_all_assets
from intelligence_engine.v4.attack_graph_engine import build_attack_graph
from intelligence_engine.v4.vulnerability_intelligence import analyze_technologies
from intelligence_engine.v4.api_discovery import scan_all_assets as discover_apis
from intelligence_engine.v4.js_intelligence import analyze_asset_js


def _step(label, func, *args, **kwargs):
    try:
        t = time.time()
        result = func(*args, **kwargs)
        print(f"  [✓] {label} ({round(time.time()-t,2)}s)")
        return result
    except Exception as e:
        print(f"  [!] {label} failed: {e}")
        return {}


def run_v4(profile: dict,
           enable_vuln_intel: bool = False,
           enable_api_discovery: bool = True,
           enable_js_intel: bool = False,
           max_api_assets: int = 5) -> dict:

    domain = profile.get("asset", "unknown")
    start  = time.time()

    print(f"\n{'='*62}")
    print(f"  SentinelX V4 Intelligence Engine")
    print(f"  Domain: {domain}")
    print(f"{'='*62}\n")

    report = {
        "domain":       domain,
        "engine":       "SentinelX V4 Intelligence Engine",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    # 1. Asset Correlation
    print("[1/6] Asset Correlation")
    correlation = _step("Correlate by IP / cert / cloud / tech",
                         correlate_assets, profile)
    report["asset_correlation"] = {
        "ip_clusters":    correlation.get("ip_clusters", {}),
        "cloud_clusters": correlation.get("cloud_clusters", {}),
        "total_assets":   correlation.get("total_assets", 0),
        "assets":         correlation.get("assets", []),
    }

    # 2. Exposure Scoring
    print("\n[2/6] Internet Exposure Scoring")
    exposure = _step("Score each asset 0-100",
                      score_all_assets, correlation.get("assets", []))
    report["exposure_scores"] = exposure

    # 3. Attack Graph
    print("\n[3/6] Attack Graph Engine")
    attack_graph = _step("Build evidence-only attack chains",
                          build_attack_graph, profile)
    report["attack_graph"] = attack_graph

    # 4. Vulnerability Intelligence (live NVD — optional)
    print("\n[4/6] Vulnerability Intelligence")
    if enable_vuln_intel:
        all_techs = list({
            (t["name"] if isinstance(t, dict) else t)
            for asset in correlation.get("assets", [])
            for t in asset.get("technologies", [])
        })
        tech_dicts = [{"name": t} for t in all_techs if t]
        vuln_intel = _step(f"NVD lookup for {len(tech_dicts)} technologies",
                            analyze_technologies, tech_dicts, True)
    else:
        vuln_intel = {"note": "Disabled — pass enable_vuln_intel=True to enable (requires internet)"}
    report["vulnerability_intelligence"] = vuln_intel

    # 5. API Discovery
    print("\n[5/6] API Discovery")
    if enable_api_discovery:
        top_assets = sorted(
            correlation.get("assets", []),
            key=lambda x: x.get("risk_score", 0), reverse=True
        )[:max_api_assets]
        api_results = _step(f"Probe APIs on {len(top_assets)} assets",
                             discover_apis, top_assets, max_api_assets)
    else:
        api_results = {"note": "Disabled — pass enable_api_discovery=True to enable"}
    report["api_discovery"] = api_results

    # 6. JavaScript Intelligence
    print("\n[6/6] JavaScript Intelligence")
    if enable_js_intel:
        top_host = (correlation.get("assets", [{}]) or [{}])[0].get("host", domain)
        js_result = _step(f"Extract secrets + endpoints from {top_host}",
                           analyze_asset_js, top_host)
    else:
        js_result = {"note": "Disabled — pass enable_js_intel=True to enable"}
    report["js_intelligence"] = js_result

    report["v4_duration_seconds"] = round(time.time() - start, 2)

    _print_v4_summary(report)
    return report


def _print_v4_summary(r: dict):
    ag = r.get("attack_graph", {})
    exp = r.get("exposure_scores", [])
    print(f"\n{'='*62}")
    print("  V4 Intelligence Complete")
    print(f"{'='*62}")
    print(f"  Attack Chains  : {ag.get('total_chains', 0)}")
    print(f"  Critical Chains: {ag.get('summary', {}).get('critical_chains', 0)}")
    print(f"  Top Entry Point: {ag.get('summary', {}).get('top_entry_point')}")
    print(f"  Top Chain      : {ag.get('summary', {}).get('top_chain')}")
    if exp:
        top = exp[0]
        print(f"  Most Exposed   : {top['host']} ({top['exposure_score']}/100 {top['exposure_level']})")
    print(f"  Duration       : {r['v4_duration_seconds']}s")
    print(f"{'='*62}\n")


def save_v4_report(report: dict) -> str:
    os.makedirs("reports", exist_ok=True)
    domain = report.get("domain", "unknown")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"reports/{domain}_v4_{ts}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, default=str)
    print(f"[+] V4 report saved: {path}")
    return path
