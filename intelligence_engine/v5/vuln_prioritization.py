"""
SentinelX V5 — Vulnerability Prioritization Engine

Combines NVD CVE data with:
  - EPSS (probability of exploitation in the wild)
  - CISA KEV (known actively exploited vulnerabilities)
  - CVSS v3 base score
  - Asset criticality (exposure score)
  - Internet exposure (is the service public?)

Output: Prioritized vulnerability list with remediation urgency.

Priority formula:
  P = (kev_weight * 40) + (epss * 30) + (cvss_norm * 20) + (exposure_norm * 10)
"""

import json
import urllib.request
import urllib.parse
import urllib.error
import time
from datetime import datetime, timezone


NVD_API    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API   = "https://api.first.org/data/v1/epss"

# Expanded CPE mappings — version-aware
TECH_CPE_KEYWORDS = {
    "Apache":       "apache http_server",
    "Nginx":        "nginx nginx",
    "WordPress":    "wordpress wordpress",
    "OpenSSH":      "openbsd openssh",
    "MySQL":        "oracle mysql",
    "MariaDB":      "mariadb mariadb",
    "PostgreSQL":   "postgresql postgresql",
    "PHP":          "php php",
    "Node.js":      "nodejs node.js",
    "Express.js":   "expressjs express",
    "Bootstrap":    "twbs bootstrap",
    "jQuery":       "jquery jquery",
    "React":        "facebook react",
    "Tomcat":       "apache tomcat",
    "Jenkins":      "jenkins jenkins",
    "OpenSSL":      "openssl openssl",
    "IIS":          "microsoft iis",
    "LiteSpeed":    "litespeedtech litespeed_web_server",
    "Cloudflare":   None,
    "Akamai":       None,
}

USER_AGENT = "SentinelX-ASM/5.0"


def _fetch_json(url: str, timeout: int = 12) -> dict | list:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"error": str(e)}


def fetch_cisa_kev() -> tuple[set, dict]:
    """Returns (set of CVE IDs, dict of CVE→details)."""
    data = _fetch_json(CISA_KEV, timeout=20)
    if "vulnerabilities" not in data:
        return set(), {}
    kev_ids = set()
    kev_details = {}
    for v in data["vulnerabilities"]:
        cid = v.get("cveID")
        if cid:
            kev_ids.add(cid)
            kev_details[cid] = {
                "vendor_project": v.get("vendorProject"),
                "product":        v.get("product"),
                "vulnerability_name": v.get("vulnerabilityName"),
                "date_added":     v.get("dateAdded"),
                "due_date":       v.get("dueDate"),
                "notes":          v.get("notes"),
            }
    return kev_ids, kev_details


def lookup_cves_nvd(keyword: str, max_results: int = 8) -> list:
    params = urllib.parse.urlencode({
        "keywordSearch":  keyword,
        "resultsPerPage": max_results,
    })
    data = _fetch_json(f"{NVD_API}?{params}", timeout=20)
    if "vulnerabilities" not in data:
        return []

    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        desc   = next((d["value"] for d in cve.get("descriptions", [])
                       if d.get("lang") == "en"), "")[:300]
        metrics = cve.get("metrics", {})
        cvss_score = None
        severity   = "UNKNOWN"
        for ver in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            m = metrics.get(ver, [])
            if m:
                cvss_score = m[0]["cvssData"].get("baseScore")
                severity   = m[0]["cvssData"].get("baseSeverity", "UNKNOWN")
                break

        cves.append({
            "cve_id":      cve_id,
            "description": desc,
            "cvss_score":  cvss_score,
            "severity":    severity,
            "published":   cve.get("published", "")[:10],
            "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })
    return cves


def fetch_epss(cve_ids: list) -> dict:
    if not cve_ids:
        return {}
    ids = ",".join(cve_ids[:30])
    data = _fetch_json(f"{EPSS_API}?cve={ids}", timeout=15)
    result = {}
    for item in data.get("data", []):
        result[item["cve"]] = {
            "epss":       float(item.get("epss", 0)),
            "percentile": float(item.get("percentile", 0)),
        }
    return result


def prioritize_vulnerability(cve: dict, kev_ids: set, kev_details: dict,
                              epss_map: dict, asset_exposure: int) -> dict:
    cve_id     = cve["cve_id"]
    cvss       = float(cve.get("cvss_score") or 0)
    in_kev     = cve_id in kev_ids
    epss_data  = epss_map.get(cve_id, {"epss": 0, "percentile": 0})
    epss_score = epss_data["epss"]

    # Priority score 0-100
    kev_pts      = 40 if in_kev else 0
    epss_pts     = round(epss_score * 30, 1)
    cvss_pts     = round((cvss / 10) * 20, 1)
    exposure_pts = round((asset_exposure / 100) * 10, 1)
    priority     = min(100, kev_pts + epss_pts + cvss_pts + exposure_pts)

    if priority >= 70 or in_kev:
        urgency = "IMMEDIATE"
    elif priority >= 45:
        urgency = "URGENT"
    elif priority >= 25:
        urgency = "PLANNED"
    else:
        urgency = "MONITOR"

    return {
        **cve,
        "in_kev":          in_kev,
        "kev_details":     kev_details.get(cve_id),
        "epss_score":      epss_score,
        "epss_percentile": epss_data["percentile"],
        "priority_score":  priority,
        "urgency":         urgency,
        "asset_exposure":  asset_exposure,
    }


def run_vuln_prioritization(profile: dict) -> dict:
    """
    Full vulnerability prioritization pipeline:
      1. Collect all technologies from scan
      2. NVD CVE lookup per technology
      3. CISA KEV check
      4. EPSS scoring
      5. Priority ranking
    """
    print("    → Fetching CISA KEV list...")
    kev_ids, kev_details = fetch_cisa_kev()
    print(f"    → KEV has {len(kev_ids)} entries")

    # Collect all unique technologies
    tech_set: set[str] = set()
    for asset in profile.get("subdomain_assets", {}).get("assets", []):
        for t in asset.get("http", {}).get("technologies", []):
            name = t["name"] if isinstance(t, dict) else t
            if name and TECH_CPE_KEYWORDS.get(name) is not None:
                tech_set.add(name)
    # Also from main domain tech
    for t in profile.get("technology_intelligence", {}).get("technology", {}).get("detected_frameworks", []):
        name = t["name"] if isinstance(t, dict) else t
        if name:
            tech_set.add(name)

    # Build asset exposure map
    asset_exposure: dict[str, int] = {}
    for asset in profile.get("subdomain_assets", {}).get("assets", []):
        host  = asset.get("host", "")
        score = asset.get("infrastructure", {}).get("exposure_score", 50)
        asset_exposure[host] = score

    all_cves    = []
    tech_results = []

    for tech in sorted(tech_set):
        kw = TECH_CPE_KEYWORDS.get(tech, tech)
        if not kw:
            continue
        print(f"    → NVD lookup: {tech}...")
        cves = lookup_cves_nvd(kw, max_results=5)
        time.sleep(0.7)   # NVD rate limit

        # EPSS
        cve_ids = [c["cve_id"] for c in cves]
        epss_map = fetch_epss(cve_ids) if cve_ids else {}

        # Prioritize each CVE
        exposure = max(asset_exposure.values(), default=50) if asset_exposure else 50
        prioritized = [
            prioritize_vulnerability(c, kev_ids, kev_details, epss_map, exposure)
            for c in cves
        ]
        prioritized.sort(key=lambda x: x["priority_score"], reverse=True)
        all_cves.extend(prioritized)

        tech_results.append({
            "technology":  tech,
            "cve_count":   len(cves),
            "kev_count":   sum(1 for c in prioritized if c["in_kev"]),
            "top_cve":     prioritized[0]["cve_id"] if prioritized else None,
            "top_priority": prioritized[0]["priority_score"] if prioritized else 0,
            "cves":        prioritized,
        })

    # Deduplicate and sort all CVEs
    seen = set()
    unique_cves = []
    for c in all_cves:
        if c["cve_id"] not in seen:
            seen.add(c["cve_id"])
            unique_cves.append(c)
    unique_cves.sort(key=lambda x: x["priority_score"], reverse=True)

    kev_found = [c for c in unique_cves if c["in_kev"]]
    immediate  = [c for c in unique_cves if c["urgency"] == "IMMEDIATE"]

    return {
        "timestamp":         datetime.now(timezone.utc).isoformat(),
        "technologies_scanned": sorted(tech_set),
        "total_cves":        len(unique_cves),
        "kev_matched":       len(kev_found),
        "immediate_action":  len(immediate),
        "kev_vulnerabilities": kev_found[:10],
        "top_vulnerabilities": unique_cves[:20],
        "by_technology":     tech_results,
        "findings": [
            {
                "issue":    f"KEV vulnerability: {c['cve_id']} in {c.get('description','')[:80]}",
                "severity": "CRITICAL",
                "evidence": f"EPSS {c['epss_score']:.3f} · CVSS {c.get('cvss_score')} · CISA KEV",
            }
            for c in kev_found[:5]
        ],
    }
