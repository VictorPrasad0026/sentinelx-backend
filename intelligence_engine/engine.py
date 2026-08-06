"""
SentinelX Intelligence Engine v2 — Main Orchestrator

Full Phase 2 pipeline:

  1.  Knowledge Graph       graph_builder
  2.  Attack Surface        attack_surface_mapper
  3.  Internet Exposure     internet_exposure
  4.  Trust Relationships   trust_relationships
  5.  Business Asset Map    business_asset_mapper
  6.  Attack Paths          attack_path_builder + validator + ranker
  7.  Attack Chains         attack_chain_generator
  8.  Lateral Movement      lateral_movement
  9.  Privilege Escalation  privilege_escalation
  10. Persistence Risks     persistence_engine
  11. Business Impact       business_impact
  12. Crown Jewels          crown_jewel_identifier
  13. Compliance Map        compliance_mapper
  14. Remediation Plan      remediation_engine + fix_prioritizer + risk_reduction_calculator
  15. AI Executive Summary  executive_summary (LLM)
  16. Snapshot + Change     snapshot_manager + change_detector + trend_engine
  17. Neo4j (optional)      neo4j_client

Entry: run(profile) -> intelligence_report dict
"""

import json
import os
import time
from datetime import datetime, timezone

# Graph
from intelligence_engine.graph.graph_builder import build_graph
from intelligence_engine.graph.graph_updater import compute_diff
from intelligence_engine.graph.neo4j_client import Neo4jClient

# Intelligence
from intelligence_engine.intelligence.attack_surface_mapper import map_attack_surface
from intelligence_engine.intelligence.internet_exposure import build_exposure_inventory
from intelligence_engine.intelligence.trust_relationships import analyze_trust_relationships

# Business
from intelligence_engine.business.business_impact import generate_business_impact
from intelligence_engine.business.business_asset_mapper import map_all_assets
from intelligence_engine.business.crown_jewel_identifier import identify_crown_jewels
from intelligence_engine.business.compliance_mapper import ComplianceMapper

# Attack
from intelligence_engine.attack_engine.attack_path_builder import build_attack_paths
from intelligence_engine.attack_engine.attack_path_validator import validate_paths
from intelligence_engine.attack_engine.attack_path_ranker import rank_paths
from intelligence_engine.attack_engine.attack_chain_generator import generate_attack_chains
from intelligence_engine.attack_engine.lateral_movement import find_all_lateral_paths
from intelligence_engine.attack_engine.privilege_escalation import find_escalation_paths
from intelligence_engine.attack_engine.persistence_engine import find_persistence_risks

# Remediation
from intelligence_engine.remediation.remediation_engine import generate_remediation_plan
from intelligence_engine.remediation.fix_prioritizer import FixPrioritizer
from intelligence_engine.remediation.risk_reduction_calculator import RiskReductionCalculator

# Timeline
from intelligence_engine.timeline.snapshot_manager import (
    save_snapshot, load_snapshots, previous_snapshot
)
from intelligence_engine.timeline.change_detector import detect_changes
from intelligence_engine.timeline.trend_engine import TrendEngine

# AI
from intelligence_engine.ai.executive_summary import generate_executive_summary
from intelligence_engine.ai.security_copilot import ask as copilot_ask


def _step(label: str, func, *args, **kwargs):
    try:
        t = time.time()
        result = func(*args, **kwargs)
        print(f"  [✓] {label} ({round(time.time()-t,2)}s)")
        return result
    except Exception as e:
        print(f"  [!] {label} failed: {e}")
        return {} if not args else []


def run(profile: dict,
        neo4j_uri: str = None,
        neo4j_user: str = "neo4j",
        neo4j_password: str = "password",
        enable_ai: bool = True) -> dict:

    domain = profile.get("asset", "unknown")
    start  = time.time()

    print(f"\n{'='*62}")
    print(f"  SentinelX Intelligence Engine v2")
    print(f"  Domain: {domain}")
    print(f"{'='*62}\n")

    report = {
        "domain":        domain,
        "engine":        "SentinelX Intelligence Engine v2.0",
        "generated_at":  datetime.now(timezone.utc).isoformat(),
        "scan_metadata": profile.get("scan_metadata", {}),
        "risk_assessment": profile.get("risk_assessment", {}),
    }

    # ── 1. Knowledge Graph ──────────────────────────────────────
    print("[1/17] Knowledge Graph")
    graph = _step("Build + dedup + relationship discovery", build_graph, profile)
    report["knowledge_graph"] = {
        "statistics": graph.get("statistics", {}),
        "validation": graph.get("validation", {}),
        "nodes":      graph.get("nodes", []),
        "edges":      graph.get("edges", []),
    }

    # ── 2. Attack Surface ───────────────────────────────────────
    print("\n[2/17] Attack Surface")
    attack_surface = _step("Criticality + exposure per asset", map_attack_surface, graph, profile)
    report["attack_surface_intelligence"] = attack_surface

    # ── 3. Internet Exposure Inventory ──────────────────────────
    print("\n[3/17] Internet Exposure Inventory")
    exposure_inventory = _step("Build exposure inventory", build_exposure_inventory, graph, profile)
    report["exposure_inventory"] = exposure_inventory

    # ── 4. Trust Relationships ──────────────────────────────────
    print("\n[4/17] Trust Relationships")
    trust_rels = _step("Analyze third-party trusts", analyze_trust_relationships, profile)
    report["trust_relationships"] = trust_rels

    # ── 5. Business Asset Map ───────────────────────────────────
    print("\n[5/17] Business Asset Map")
    biz_asset_map = _step("Map assets to business functions", map_all_assets, attack_surface)
    report["business_asset_map"] = biz_asset_map

    # ── 6. Attack Paths ─────────────────────────────────────────
    print("\n[6/17] Attack Paths")
    raw_paths     = _step("Build paths",    build_attack_paths, graph, attack_surface)
    valid_paths   = _step("Validate paths", validate_paths, raw_paths)
    ranked_paths  = _step("Rank paths",     rank_paths, valid_paths)
    report["attack_paths"] = ranked_paths

    # ── 7. Attack Chains ────────────────────────────────────────
    print("\n[7/17] Attack Chains")
    chains = _step("Compose multi-stage chains", generate_attack_chains, ranked_paths)
    report["attack_chains"] = chains

    # ── 8. Lateral Movement ─────────────────────────────────────
    print("\n[8/17] Lateral Movement")
    top_entry_hosts = [p["entry_point"] for p in ranked_paths[:5] if p.get("entry_point")]
    lateral = _step("Discover pivot paths", find_all_lateral_paths, graph, top_entry_hosts)
    report["lateral_movement"] = lateral

    # ── 9. Privilege Escalation ─────────────────────────────────
    print("\n[9/17] Privilege Escalation")
    priv_esc = _step("Find escalation paths", find_escalation_paths, graph, attack_surface)
    report["privilege_escalation"] = priv_esc

    # ── 10. Persistence Risks ───────────────────────────────────
    print("\n[10/17] Persistence Risks")
    persistence = _step("Find persistence risks", find_persistence_risks, profile, graph)
    report["persistence_risks"] = persistence

    # ── 11. Business Impact ─────────────────────────────────────
    print("\n[11/17] Business Impact")
    biz_impact = _step("Translate findings to exec language", generate_business_impact, profile, ranked_paths)
    report["business_impact"] = biz_impact

    # ── 12. Crown Jewels ────────────────────────────────────────
    print("\n[12/17] Crown Jewels")
    crown_jewels = _step("Identify crown jewels", identify_crown_jewels, attack_surface)
    report["crown_jewels"] = crown_jewels

    # ── 13. Compliance Map ──────────────────────────────────────
    print("\n[13/17] Compliance Map")
    findings = profile.get("risk_assessment", {}).get("findings", [])
    compliance = _step("Map findings to frameworks", ComplianceMapper().generate_compliance_report, findings)
    report["compliance_map"] = compliance

    # ── 14. Remediation ─────────────────────────────────────────
    print("\n[14/17] Remediation Plan")
    remediation   = _step("Generate plan",           generate_remediation_plan, findings, ranked_paths)
    prioritized   = _step("Prioritize by ROI",       FixPrioritizer().prioritize, findings)
    risk_calc     = _step("Calculate risk reduction", RiskReductionCalculator().calculate, findings, prioritized)
    report["remediation_plan"] = {
        **remediation,
        "prioritized_fixes":    prioritized,
        "risk_reduction_calc":  risk_calc,
    }

    # ── 15. AI Layer ────────────────────────────────────────────
    print("\n[15/17] AI Analysis")
    if enable_ai:
        exec_summary = _step("Executive summary", generate_executive_summary, biz_impact)
        report["ai_executive_summary"] = exec_summary
    else:
        report["ai_executive_summary"] = (
            "AI disabled. Set enable_ai=True and ANTHROPIC_API_KEY to enable."
        )

    # ── 16. Snapshot + Changes + Trend ──────────────────────────
    print("\n[16/17] Timeline")
    snapshot_path = _step("Save snapshot", save_snapshot, domain, report)
    report["snapshot_path"] = snapshot_path

    prev = previous_snapshot(domain)
    changes = (_step("Detect changes", detect_changes, prev, report)
               if prev else {"status": "FIRST_SCAN", "summary": "No previous snapshot."})
    report["changes"] = changes

    snapshots = load_snapshots(domain)
    trend = _step("Trend analysis", TrendEngine().analyze, snapshots)
    report["trend"] = trend

    # ── 17. Neo4j (optional) ────────────────────────────────────
    print("\n[17/17] Neo4j")
    if neo4j_uri:
        try:
            client = Neo4jClient(neo4j_uri, neo4j_user, neo4j_password)
            neo4j_result = client.write_graph(graph, domain)
            client.close()
            report["neo4j"] = neo4j_result
        except Exception as e:
            report["neo4j"] = {"status": "FAILED", "error": str(e)}
    else:
        report["neo4j"] = {
            "status": "SKIPPED",
            "tip":    "Pass neo4j_uri='bolt://localhost:7687' to write to graph DB",
        }

    report["engine_duration_seconds"] = round(time.time() - start, 2)
    _print_summary(report)
    return report


def _print_summary(r: dict):
    stats = r.get("knowledge_graph", {}).get("statistics", {})
    print(f"\n{'='*62}")
    print("  Intelligence Engine Complete")
    print(f"{'='*62}")
    print(f"  Domain              : {r['domain']}")
    print(f"  Risk Score          : {r['risk_assessment'].get('risk_score')} / {r['risk_assessment'].get('severity')}")
    print(f"  Graph Nodes         : {stats.get('total_nodes')}")
    print(f"  Graph Edges         : {stats.get('total_edges')}")
    print(f"  Crown Jewels        : {r.get('crown_jewels', {}).get('crown_jewel_count')}")
    print(f"  Attack Paths        : {len(r.get('attack_paths', []))}")
    print(f"  Attack Chains       : {len(r.get('attack_chains', []))}")
    print(f"  Lateral Pivots      : {r.get('lateral_movement', {}).get('total_pivot_opportunities')}")
    print(f"  Priv-Esc Paths      : {len(r.get('privilege_escalation', []))}")
    print(f"  Persistence Risks   : {len(r.get('persistence_risks', []))}")
    print(f"  Trust Relationships : {r.get('trust_relationships', {}).get('total_trust_relationships')}")
    print(f"  Remediations        : {r.get('remediation_plan', {}).get('total_remediations')}")
    print(f"  Changes             : {r.get('changes', {}).get('summary', 'N/A')}")
    print(f"  Duration            : {r['engine_duration_seconds']}s")
    print(f"  Snapshot            : {r.get('snapshot_path')}")
    print(f"{'='*62}\n")


def save_intelligence_report(report: dict) -> str:
    os.makedirs("reports", exist_ok=True)
    domain = report.get("domain", "unknown")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join("reports", f"{domain}_intelligence_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, default=str)
    print(f"[+] Intelligence report saved: {path}")
    return path
