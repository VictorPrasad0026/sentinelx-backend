"""
SentinelX V5 — Single Command Runner

Run:
    python3 run.py

Flags:
    python3 run.py example.com              # direct domain
    python3 run.py example.com --no-ai      # skip LLM copilot
    python3 run.py example.com --vuln       # NVD CVE lookup (slower)
    python3 run.py example.com --github     # GitHub leak search
    python3 run.py example.com --screenshots# capture screenshots (needs playwright)
    python3 run.py example.com --no-passive # skip passive DNS
    python3 run.py example.com --neo4j      # write to Neo4j

AI Copilot key (pick one):
    export GROQ_API_KEY=gsk_...
    export GEMINI_API_KEY=AIza...
    export ANTHROPIC_API_KEY=sk-ant-...
"""

import sys
import os
import json
import time
import textwrap
from datetime import datetime


def main():
    args = sys.argv[1:]
    domain            = None
    enable_ai         = True
    use_neo4j         = False
    enable_vuln       = "--vuln"       in args
    enable_github     = "--github"     in args
    enable_screenshots= "--screenshots"in args
    enable_passive    = "--no-passive" not in args

    for arg in args:
        if not arg.startswith("--"):
            domain = arg.strip().lower()
        elif arg == "--no-ai":
            enable_ai = False
        elif arg == "--neo4j":
            use_neo4j = True

    if not domain:
        print("\n" + "="*60)
        print("  SentinelX V5 — Attack Surface Management Platform")
        print("="*60)
        print()
        domain = input("  Target domain: ").strip().lower()
        domain = domain.replace("https://","").replace("http://","").rstrip("/")
    if not domain:
        print("[!] No domain provided.")
        sys.exit(1)

    # ── Check AI ───────────────────────────────────────────────
    if enable_ai:
        try:
            from intelligence_engine.ai.llm_client import is_available
            ai_ok, ai_reason = is_available()
        except Exception:
            ai_ok, ai_reason = False, "LLM client unavailable"
        if not ai_ok:
            print(f"\n  [!] AI Copilot offline — {ai_reason}")
            print(f"      Groq (free): export GROQ_API_KEY=gsk_...")
            enable_ai = False
        else:
            print(f"\n  [✓] AI Copilot ready\n")

    t_total = time.time()

    # ══════════════════════════════════════════════════
    # PHASE 1 — COLLECT
    # ══════════════════════════════════════════════════
    print(f"\n[PHASE 1/4] Collecting intelligence — {domain}")
    from collectors.asset_profile import generate_asset_profile, save_report
    profile = generate_asset_profile(domain)
    collector_path = save_report(profile)
    risk = profile.get("risk_assessment", {})
    print(f"  ✓ Risk score: {risk.get('risk_score')}/100 · {risk.get('severity')}")

    # ══════════════════════════════════════════════════
    # PHASE 2 — V3 INTELLIGENCE
    # ══════════════════════════════════════════════════
    print(f"\n[PHASE 2/4] Intelligence Engine V3 — Graph + Risk + Remediation")
    from intelligence_engine.engine import run as run_v3, save_intelligence_report
    v3_report = run_v3(profile, enable_ai=enable_ai,
                       neo4j_uri="bolt://localhost:7687" if use_neo4j else None)
    v3_path = save_intelligence_report(v3_report)

    # ══════════════════════════════════════════════════
    # PHASE 3 — V4 ATTACK GRAPH
    # ══════════════════════════════════════════════════
    print(f"\n[PHASE 3/4] Intelligence Engine V4 — Attack Graph + Correlation")
    from intelligence_engine.v4.v4_engine import run_v4, save_v4_report
    v4_report = run_v4(profile, enable_api_discovery=True)
    v4_path = save_v4_report(v4_report)

    # ══════════════════════════════════════════════════
    # PHASE 4 — V5 ENHANCED INTELLIGENCE
    # ══════════════════════════════════════════════════
    print(f"\n[PHASE 4/4] Intelligence Engine V5 — 17 Enhanced Features")
    from intelligence_engine.v5.v5_engine import run_v5, save_v5_report
    v5_report = run_v5(
        profile,
        v4_report,
        enable_screenshots  = enable_screenshots,
        enable_passive_dns  = enable_passive,
        enable_vuln_intel   = enable_vuln,
        enable_login_scan   = True,
        enable_secrets_scan = True,
        enable_github       = enable_github,
        enable_ct_timeline  = True,
        max_assets          = 8,
    )
    v5_path = save_v5_report(v5_report)

    # Save snapshot for future historical comparison
    from intelligence_engine.timeline.snapshot_manager import save_snapshot
    save_snapshot(domain, {**v3_report, "v4": v4_report, "v5": v5_report})

    elapsed = round(time.time() - t_total, 1)

    # ══════════════════════════════════════════════════
    # PRINT FULL REPORT
    # ══════════════════════════════════════════════════
    _print_report(profile, v3_report, v4_report, v5_report, elapsed)

    print(f"\n  Reports saved:")
    print(f"    {collector_path}")
    print(f"    {v3_path}")
    print(f"    {v4_path}")
    print(f"    {v5_path}")

    # ══════════════════════════════════════════════════
    # COPILOT SESSION
    # ══════════════════════════════════════════════════
    if enable_ai:
        _copilot_session(profile, v3_report, v4_report, v5_report)
    else:
        _print_evidence_summary(v3_report, v4_report, v5_report)


# ── TERMINAL REPORT ──────────────────────────────────────────

W = 64

def _line(char="─"):       print("  " + char * (W-4))
def _hdr(title):           print(); print(f"  {'━'*(W-4)}"); print(f"  {title}"); print(f"  {'━'*(W-4)}")
def _row(k, v, col=""):
    c = {"red":"\033[91m","orange":"\033[93m","green":"\033[92m","blue":"\033[94m","":"\033[0m"}.get(col,"")
    reset = "\033[0m"
    print(f"  {k:<28}{c}{v}{reset}")
def _finding(sev, issue):
    icons = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}
    print(f"  {icons.get(sev,'⚪')}  [{sev[:4]}]  {issue[:W-14]}")
def _chain(rank, pct, name, mitre):
    bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
    print(f"  #{rank:02d}  {bar}  {pct:3d}%  {name[:35]}")
    print(f"       MITRE: {' → '.join(mitre[:4])}")


def _print_report(profile, v3, v4, v5, elapsed):
    risk    = profile.get("risk_assessment", {})
    surface = profile.get("attack_surface", {})
    ag      = v4.get("attack_graph", {})
    exp_top = v4.get("exposure_scores", [])
    tls     = v5.get("tls_grades", {})
    hist    = v5.get("historical_comparison", {})
    vuln    = v5.get("vulnerability_prioritization", {})
    ap      = v5.get("enriched_attack_paths", {})
    trends  = v5.get("risk_trends", {})
    passive = v5.get("passive_dns", {})
    logins  = v5.get("login_detection", [])
    secrets = v5.get("secrets_exposure", [])

    _hdr("SENTINELX V5 — SECURITY REPORT")

    _row("Domain",        profile.get("asset",""))
    _row("Scan time",     profile.get("scan_metadata",{}).get("scan_time","")[:19])
    _row("Duration",      f"{elapsed}s total")
    _row("Risk score",    f"{risk.get('risk_score')}/100 · {risk.get('severity')}",
         "red" if (risk.get("risk_score") or 0) >= 60 else "orange")
    _row("TLS grade",     tls.get("overall_grade","N/A"))
    _row("Attack paths",  f"{ap.get('total_paths',0)} total · {ap.get('critical_paths',0)} critical")
    _row("KEV-matched",   f"{ap.get('kev_paths',0)} paths have active exploit CVEs",
         "red" if ap.get("kev_paths",0) > 0 else "")
    _row("Scan history",  f"{hist.get('scan_count',1)} scans · trend: {trends.get('direction','N/A')}")
    _row("Subdomains",    surface.get("total_subdomains", 0))

    # Historical
    if hist.get("status") != "FIRST_SCAN":
        _hdr("Historical Changes")
        _row("Risk delta",     f"{hist.get('risk_score_delta',0):+d} points")
        _row("New assets",     str(hist.get("new_assets",[])))
        _row("Removed assets", str(hist.get("removed_assets",[])))
        _row("Changed assets", f"{len(hist.get('changed_assets',[]))} assets changed")
        _row("WHOIS changes",  str(list(hist.get("whois_changes",{}).keys())))

    # TLS Grades
    _hdr("TLS Grades by Asset")
    for host, grade in list(tls.get("asset_grades",{}).items())[:10]:
        col = "red" if grade["grade"] == "F" else "orange" if grade["grade"] in ("C","D") else "green"
        _row(host[-35:], f"{grade['grade']}  ({grade.get('tls_version','?')}) {', '.join(grade.get('issues',[])[:1])}", col)

    # Findings
    _hdr("Security Findings")
    for f in risk.get("findings", []):
        _finding(f.get("severity","LOW"), f.get("issue",""))

    # V5 Findings (login/secrets)
    for f in v5.get("v5_findings",[])[:8]:
        _finding(f.get("severity","LOW"), f.get("issue",""))

    # CVEs
    if isinstance(vuln, dict) and vuln.get("kev_matched",0) > 0:
        _hdr("CISA KEV Vulnerabilities (Actively Exploited)")
        for c in vuln.get("kev_vulnerabilities",[])[:5]:
            _finding("CRITICAL", f"{c['cve_id']} — {c.get('description','')[:60]}")
            print(f"           EPSS {c.get('epss_score',0):.3f} · CVSS {c.get('cvss_score')} · KEV due: {c.get('kev_details',{}).get('due_date','?')}")

    # Attack chains
    _hdr(f"Enriched Attack Paths ({ap.get('total_paths',0)} total)")
    for p in ap.get("attack_paths",[])[:8]:
        _chain(p.get("rank",0), p.get("likelihood",0), p.get("name",""), p.get("mitre_chain",[]))
        if p.get("cve_enriched"):
            print(f"       CVE: {p.get('matched_cves',[{}])[0].get('cve_id','')} · EPSS {p.get('top_epss',0):.3f}")

    # Exposure
    _hdr("Asset Exposure Scores")
    for e in (exp_top or [])[:8]:
        bar = "█" * (e["exposure_score"] // 10) + "░" * (10 - e["exposure_score"] // 10)
        _row(e["host"][-35:], f"{bar} {e['exposure_score']}/100 {e['exposure_level']}")

    # Passive DNS
    if isinstance(passive, dict):
        hist_subs = passive.get("historical_subdomains",[])
        if hist_subs:
            _hdr(f"Historical Assets (Passive DNS — {len(hist_subs)} found)")
            for s in hist_subs[:8]:
                print(f"  · {s}")

    # Login pages
    total_logins = sum(r.get("login_count",0) for r in (logins or []) if isinstance(r,dict))
    total_default_risk = sum(r.get("default_cred_risk_count",0) for r in (logins or []) if isinstance(r,dict))
    if total_logins:
        _hdr(f"Login Pages Detected ({total_logins} found)")
        for lr in (logins or []):
            if isinstance(lr, dict):
                for l in lr.get("login_pages",[])[:3]:
                    icon = "🔴" if l.get("default_creds_risk") else "🟠"
                    print(f"  {icon}  {l.get('url','')[:55]}  [{l.get('auth_type','')}]")

    # Secrets
    total_secrets = sum(r.get("secrets_count",0) for r in (secrets or []) if isinstance(r,dict))
    total_crit    = sum(r.get("critical_count",0) for r in (secrets or []) if isinstance(r,dict))
    if total_crit or total_secrets:
        _hdr(f"Sensitive Files Exposed ({total_crit} critical)")
        for sr in (secrets or []):
            if isinstance(sr, dict):
                for f in sr.get("files_exposed",[])[:4]:
                    _finding(f.get("severity","LOW"), f"Exposed: {f.get('path','')} on {sr.get('host','')}")

    # CT Timeline
    ct = v5.get("ct_timeline",[])
    if ct and isinstance(ct, list) and isinstance(ct[0], dict) and not ct[0].get("error"):
        _hdr(f"Certificate Transparency Timeline (last {min(5,len(ct))} entries)")
        for entry in ct[:5]:
            print(f"  📜 {entry.get('logged_at','')}  {entry.get('name_value','')[:45]}  exp: {entry.get('not_after','')[:10]}")

    # Remediation
    rem = v3.get("remediation_plan",{}).get("all_remediations",[])
    if rem:
        _hdr("Prioritized Remediation Plan")
        for r in rem[:6]:
            icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(r.get("max_severity","LOW"),"⚪")
            print(f"  {icon} #{r['priority_rank']}  {r['title'][:W-10]}")
            print(f"       Effort: {r['effort']}  ·  Risk reduction: {r['risk_reduction']}%")

    _line("═")
    print()


# ── COPILOT ──────────────────────────────────────────────────

def _build_context(profile, v3, v4, v5) -> str:
    risk  = profile.get("risk_assessment", {})
    ap    = v5.get("enriched_attack_paths", {})
    vuln  = v5.get("vulnerability_prioritization", {})
    hist  = v5.get("historical_comparison", {})
    tls   = v5.get("tls_grades", {})
    logins= v5.get("login_detection", [])
    passive = v5.get("passive_dns", {})
    rem   = v3.get("remediation_plan",{}).get("all_remediations",[])[:5]
    cj    = v3.get("crown_jewels",{})

    ctx = {
        "domain":           profile.get("asset"),
        "risk_score":       risk.get("risk_score"),
        "severity":         risk.get("severity"),
        "findings":         risk.get("findings",[])[:10],
        "tls_grades":       {h: g["grade"] for h,g in tls.get("asset_grades",{}).items()},
        "attack_paths":     ap.get("attack_paths",[])[:5],
        "kev_vulns":        (vuln.get("kev_vulnerabilities",[])[:3] if isinstance(vuln,dict) else []),
        "top_cves":         (vuln.get("top_vulnerabilities",[])[:5] if isinstance(vuln,dict) else []),
        "historical_changes": hist.get("summary"),
        "risk_trend":       v5.get("risk_trends",{}).get("direction"),
        "login_pages":      [l for lr in (logins or []) if isinstance(lr,dict) for l in lr.get("login_pages",[])[:3]],
        "crown_jewels":     [a["host"] for a in cj.get("crown_jewels",[])],
        "historical_subdomains": (passive.get("historical_subdomains",[])[:10] if isinstance(passive,dict) else []),
        "remediation":      rem,
    }
    return json.dumps(ctx, indent=2, default=str)[:7000]


def _copilot_session(profile, v3, v4, v5):
    from intelligence_engine.ai.llm_client import complete
    SYSTEM = """You are SentinelX Security Copilot V5 — an AI security analyst.
Answer ONLY using the scan data provided. Never invent findings, IPs, CVEs, or assets.
If information is not in the data, say "Not found in current scan data."
Be concise, evidence-based, and useful to both technical and non-technical audiences."""

    ctx = _build_context(profile, v3, v4, v5)

    def ask(q):
        prompt = f"[SCAN DATA]\n{ctx}\n\n[QUESTION]\n{q}"
        return complete(SYSTEM, prompt, max_tokens=700)

    demos = [
        "What is my most critical asset and the single most impactful fix?",
        "Are there any actively-exploited CVEs (CISA KEV) in my technology stack?",
        "What changed since the last scan and should I be concerned?",
    ]

    print("\n" + "="*64)
    print("  SentinelX V5 Security Copilot")
    print("="*64)
    for q in demos:
        print(f"\n  Q: {q}")
        ans = ask(q)
        for line in textwrap.wrap(ans, W-4):
            print(f"  {line}")

    print(f"\n{'─'*(W-2)}")
    print("  Ask anything · type 'quit' to exit")
    print(f"{'─'*(W-2)}\n")
    while True:
        try:
            q = input("  Q: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not q or q.lower() in ("quit","exit","q"):
            break
        ans = ask(q)
        print()
        for line in textwrap.wrap(ans, W-4):
            print(f"  {line}")
        print()


def _print_evidence_summary(v3, v4, v5):
    risk = v3.get("risk_assessment",{})
    ap   = v5.get("enriched_attack_paths",{})
    vuln = v5.get("vulnerability_prioritization",{})
    rem  = v3.get("remediation_plan",{}).get("all_remediations",[])

    print("\n  ── Evidence Summary (AI disabled) ──────────────────")
    print(f"  Risk : {risk.get('risk_score')}/100 · {risk.get('severity')}")
    print(f"  Paths: {ap.get('total_paths',0)} total · {ap.get('critical_paths',0)} critical")
    if isinstance(vuln, dict):
        print(f"  CVEs : {vuln.get('total_cves',0)} · KEV: {vuln.get('kev_matched',0)}")
    if ap.get("attack_paths"):
        t = ap["attack_paths"][0]
        print(f"  Top  : {t.get('name')} ({t.get('likelihood')}%)")
    if rem:
        print(f"  Fix  : {rem[0].get('title')} · {rem[0].get('effort')}")
    print()
    print("  Enable AI: export GROQ_API_KEY=gsk_...  (free at console.groq.com)")


if __name__ == "__main__":
    main()
