"""
SentinelX Asset Profile Engine v2.0

Produces a single, complete JSON intelligence report for a domain.

Pipeline:
  Domain
    ├── Domain Intelligence   (WHOIS, NS, DNSSEC, reputation)
    ├── DNS Intelligence      (A/AAAA/MX/TXT/NS/SOA/CAA/SRV/SPF/DMARC)
    ├── SSL Intelligence      (cert, TLS, cipher, SAN, fingerprint)
    ├── HTTP Intelligence     (headers, WAF, cookies, tech)
    ├── Technology Intel      (frameworks, CSP, security posture)
    ├── CSP Intelligence      (directive analysis, risk)
    ├── Email Intelligence    (MX, SPF, DMARC, DKIM, SMTP)
    ├── Infrastructure Intel  (IP, ASN, GeoIP, Cloud, CDN, ports, exposure)
    ├── Subdomain Discovery   (crtsh, certspotter, OTX, bruteforce, permutation, zone)
    ├── Subdomain Enrichment  (full per-asset scan)
    ├── Risk Engine           (scored findings across all modules)
    ├── Asset Graph           (nodes + edges)
    └── Attack Surface Summary
"""

import json
import os
import time
from datetime import datetime, timezone

from collectors.domain_intelligence import get_domain_info
from collectors.dns_intelligence import get_dns_info
from collectors.ssl_intelligence import get_ssl_info
from collectors.http_intelligence import get_http_info
from collectors.technology_intelligence import get_technology_info
from collectors.csp_intelligence import analyze_csp
from collectors.email_intelligence import get_email_intelligence
from collectors.infrastructure_intelligence import get_infrastructure_info
from collectors.subdomain_intelligence import get_subdomains
from collectors.subdomain_asset_enrichment import enrich_all_subdomains
from collectors.risk_engine import calculate_risk
from collectors.asset_graph import create_asset_graph


# ============================================================
# SAFE COLLECTOR RUNNER
# ============================================================

def run_collector(name, func, *args):
    try:
        print(f"  [+] {name}...")
        start = time.time()
        result = func(*args)
        elapsed = round(time.time() - start, 2)
        print(f"  [✓] {name} ({elapsed}s)")
        return result
    except Exception as e:
        print(f"  [!] {name} failed: {e}")
        return {"error": str(e)}


# ============================================================
# ATTACK SURFACE SUMMARY
# ============================================================

def build_attack_surface(profile):

    assets = profile.get("subdomain_assets", {}).get("assets", [])

    summary = {
        "total_subdomains": profile.get("subdomain_intelligence", {}).get("total_subdomains", 0),
        "resolved_assets": len(assets),
        "open_ports_summary": [],
        "technologies_detected": profile.get("technology_intelligence", {}).get("technology", {}).get("detected_frameworks", []),
        "email_provider": profile.get("email_intelligence", {}).get("mx", {}).get("provider"),
        "email_risk_score": profile.get("email_intelligence", {}).get("risk", {}).get("score"),
        "cloud_provider": None,
        "cdn_provider": None,
        "waf_detected": False,
        "waf_provider": None,
        "invalid_ssl_assets": [],
        "missing_hsts_assets": [],
        "missing_csp_assets": [],
        "sensitive_assets": [],
        "critical_ports": [],
        "exposure_score": profile.get("infrastructure_intelligence", {}).get("exposure_score", 0)
    }

    # Cloud / CDN from infrastructure
    infra = profile.get("infrastructure_intelligence", {})
    cloud = infra.get("cloud", {})
    cdn = infra.get("cdn", {})

    if isinstance(cloud, dict):
        p = cloud.get("provider")
        if p and p != "UNKNOWN":
            summary["cloud_provider"] = p

    if isinstance(cdn, dict) and cdn.get("detected"):
        summary["cdn_provider"] = cdn.get("provider")

    # WAF from http
    http = profile.get("http_intelligence", {})
    waf = http.get("waf", {})
    if isinstance(waf, dict) and waf.get("detected"):
        summary["waf_detected"] = True
        summary["waf_provider"] = waf.get("provider")

    # Open ports from infrastructure
    ports_data = infra.get("ports", {})
    for p in ports_data.get("ports", []):
        if p.get("state") == "OPEN":
            entry = {
                "port": p.get("port"),
                "service": p.get("service"),
                "risk": p.get("risk")
            }
            summary["open_ports_summary"].append(entry)
            if p.get("risk") in ["CRITICAL", "HIGH"]:
                summary["critical_ports"].append(entry)

    # Per-subdomain analysis
    for asset in assets:
        host = asset.get("host", "")
        ssl_info = asset.get("ssl", {})
        http_info = asset.get("http", {})
        risk = asset.get("risk", {})

        if ssl_info.get("status") not in ("VALID",):
            summary["invalid_ssl_assets"].append(host)

        sec_headers = http_info.get("security_headers", {})
        if not sec_headers.get("strict-transport-security", {}).get("present"):
            summary["missing_hsts_assets"].append(host)
        if not sec_headers.get("content-security-policy", {}).get("present"):
            summary["missing_csp_assets"].append(host)

        for finding in risk.get("findings", []):
            if "Sensitive hostname" in finding.get("issue", ""):
                summary["sensitive_assets"].append(host)
                break

    return summary


# ============================================================
# MAIN PROFILE ENGINE
# ============================================================

def generate_asset_profile(domain):

    start = time.time()

    print(f"\n{'='*60}")
    print(f"  SentinelX ASM Scan: {domain}")
    print(f"{'='*60}\n")

    profile = {
        "asset": domain,
        "scan_metadata": {
            "scanner": "SentinelX ASM Platform",
            "version": "2.0",
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": None
        },
        "domain_intelligence": {},
        "dns_intelligence": {},
        "ssl_intelligence": {},
        "http_intelligence": {},
        "technology_intelligence": {},
        "csp_intelligence": {},
        "email_intelligence": {},
        "infrastructure_intelligence": {},
        "subdomain_intelligence": {},
        "subdomain_assets": {},
        "risk_assessment": {},
        "asset_graph": {},
        "attack_surface": {}
    }

    print("[1/10] Domain Intelligence")
    profile["domain_intelligence"] = run_collector(
        "WHOIS + NS + DNSSEC + Reputation", get_domain_info, domain
    )

    print("\n[2/10] DNS Intelligence")
    profile["dns_intelligence"] = run_collector(
        "A/AAAA/MX/TXT/NS/SOA/CAA/SRV/SPF/DMARC", get_dns_info, domain
    )

    print("\n[3/10] SSL Intelligence")
    profile["ssl_intelligence"] = run_collector(
        "Certificate + TLS + Cipher + SAN + Fingerprint", get_ssl_info, domain
    )

    print("\n[4/10] HTTP Intelligence")
    profile["http_intelligence"] = run_collector(
        "Headers + WAF + Cookies + Technologies", get_http_info, domain
    )

    print("\n[5/10] Technology Intelligence")
    technology = run_collector(
        "Frameworks + Security Posture + CSP", get_technology_info, domain
    )
    profile["technology_intelligence"] = technology

    # CSP from technology result
    print("\n[5b] CSP Intelligence")
    try:
        csp_raw = technology.get("csp_raw", {})
        if isinstance(csp_raw, dict):
            csp_enabled = csp_raw.get("enabled", False)
            csp_value = csp_raw.get("value")
        else:
            csp_enabled = bool(csp_raw)
            csp_value = csp_raw

        if csp_enabled and csp_value:
            profile["csp_intelligence"] = analyze_csp(csp_value)
        else:
            profile["csp_intelligence"] = {
                "enabled": False,
                "risk_level": "UNKNOWN",
                "directives": {},
                "trusted_domains": [],
                "message": "Content Security Policy not detected"
            }
    except Exception as e:
        profile["csp_intelligence"] = {"enabled": False, "error": str(e)}

    print("\n[6/10] Email Intelligence")
    profile["email_intelligence"] = run_collector(
        "MX + SPF + DMARC + DKIM + SMTP", get_email_intelligence, domain
    )

    print("\n[7/10] Infrastructure Intelligence")
    profile["infrastructure_intelligence"] = run_collector(
        "IP + ASN + GeoIP + Cloud + CDN + Ports + Exposure", get_infrastructure_info, domain
    )

    print("\n[8/10] Subdomain Discovery")
    subdomains = run_collector(
        "crtsh + certspotter + OTX + bruteforce + permutation + zone",
        get_subdomains, domain
    )
    profile["subdomain_intelligence"] = subdomains

    print("\n[9/10] Subdomain Asset Enrichment")
    if isinstance(subdomains, dict) and subdomains.get("subdomains"):
        profile["subdomain_assets"] = run_collector(
            f"Enriching {len(subdomains['subdomains'])} assets",
            enrich_all_subdomains, subdomains
        )
    else:
        profile["subdomain_assets"] = {"total_assets": 0, "assets": []}

    print("\n[10/10] Risk + Graph + Surface")
    profile["risk_assessment"] = run_collector("Risk Engine", calculate_risk, profile)
    profile["asset_graph"] = run_collector("Asset Graph", create_asset_graph, profile)
    profile["attack_surface"] = build_attack_surface(profile)

    profile["scan_metadata"]["duration_seconds"] = round(time.time() - start, 2)

    print(f"\n{'='*60}")
    print(f"  Scan complete in {profile['scan_metadata']['duration_seconds']}s")
    print(f"  Risk Score : {profile['risk_assessment'].get('risk_score')}")
    print(f"  Severity   : {profile['risk_assessment'].get('severity')}")
    print(f"  Subdomains : {profile['attack_surface'].get('total_subdomains')}")
    print(f"  Assets     : {profile['attack_surface'].get('resolved_assets')}")
    print(f"{'='*60}\n")

    return profile


# ============================================================
# SAVE REPORT
# ============================================================

def save_report(profile):
    os.makedirs("reports", exist_ok=True)
    filename = (
        f"{profile['asset']}_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    path = os.path.join("reports", filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(profile, f, indent=4, default=str)
    print(f"[+] Report saved: {path}")
    return path


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    target = input("Enter target domain: ").strip().lower()
    result = generate_asset_profile(target)
    path = save_report(result)
    print(f"\nFull report: {path}")
