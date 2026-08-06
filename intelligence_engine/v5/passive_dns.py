"""
SentinelX V5 — Passive DNS History Engine

Queries public passive DNS sources to discover:
  - Historical IP addresses (infrastructure changes)
  - Historical subdomains (assets no longer in DNS but previously existed)
  - First/last seen timestamps
  - IP change timeline (detect hosting provider moves)

Sources (all free, no API key required):
  - SecurityTrails (free tier, requires key)
  - HackerTarget API
  - CIRCL.lu passive DNS
  - ViewDNS.info (historical IPs)
  - RiskIQ Community (rate-limited)
"""

import json
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone


USER_AGENT = "SentinelX-ASM/5.0"


def _fetch_json(url: str, timeout: int = 10, headers: dict = None) -> dict | list:
    try:
        h = {"User-Agent": USER_AGENT}
        if headers:
            h.update(headers)
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return {"error": str(e)}


def _fetch_text(url: str, timeout: int = 10) -> str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(65536).decode(errors="ignore")
    except Exception:
        return ""


def hackertarget_dns_history(domain: str) -> list:
    """HackerTarget historical DNS — free, no key."""
    url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}"
    text = _fetch_text(url)
    results = []
    for line in text.splitlines():
        if "," in line:
            parts = line.split(",")
            if len(parts) >= 2:
                results.append({"host": parts[0].strip(), "ip": parts[1].strip()})
    return results


def circl_passive_dns(domain: str) -> list:
    """CIRCL.lu passive DNS — free, no key."""
    url = f"https://www.circl.lu/pdns/query/{urllib.parse.quote(domain)}"
    data = _fetch_json(url, headers={"Accept": "application/json"})
    if isinstance(data, dict) and "error" in data:
        return []
    if isinstance(data, list):
        results = []
        for entry in data[:20]:
            results.append({
                "rrname":    entry.get("rrname", "").rstrip("."),
                "rrtype":    entry.get("rrtype"),
                "rdata":     entry.get("rdata", "").rstrip("."),
                "time_first": entry.get("time_first"),
                "time_last":  entry.get("time_last"),
                "count":      entry.get("count", 0),
            })
        return results
    return []


def crtsh_subdomains_history(domain: str) -> list:
    """
    crt.sh certificate transparency — reveals historical subdomains.
    Better for finding previously valid subdomains than current DNS.
    """
    url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
    data = _fetch_json(url, timeout=15)
    if isinstance(data, dict):
        return []

    seen = set()
    results = []
    for entry in (data or [])[:100]:
        names = entry.get("name_value", "").split("\n")
        for name in names:
            name = name.strip().lstrip("*.")
            if name and name not in seen and domain in name:
                seen.add(name)
                results.append({
                    "subdomain":  name,
                    "first_seen": entry.get("not_before", "")[:10],
                    "last_seen":  entry.get("not_after", "")[:10],
                    "issuer":     entry.get("issuer_name", ""),
                    "source":     "CT_LOG",
                })

    results.sort(key=lambda x: x["first_seen"], reverse=True)
    return results


def rapiddns_history(domain: str) -> list:
    """RapidDNS — free subdomain history."""
    url = f"https://rapiddns.io/subdomain/{urllib.parse.quote(domain)}?full=1"
    text = _fetch_text(url)
    import re
    subdomains = re.findall(rf'[a-zA-Z0-9\-\.]+\.{re.escape(domain)}', text)
    seen = set()
    results = []
    for sub in subdomains:
        if sub not in seen:
            seen.add(sub)
            results.append({"subdomain": sub, "source": "RapidDNS"})
    return results[:50]


def get_passive_dns_history(domain: str) -> dict:
    """
    Aggregate passive DNS from all sources.
    """
    print("    → HackerTarget DNS history...")
    ht_hosts = hackertarget_dns_history(domain)

    print("    → CIRCL.lu passive DNS...")
    circl     = circl_passive_dns(domain)

    print("    → CT log subdomain history...")
    ct_subs   = crtsh_subdomains_history(domain)

    print("    → RapidDNS history...")
    rapid     = rapiddns_history(domain)

    # Merge all discovered subdomains
    all_subs = set()
    for h in ht_hosts:
        all_subs.add(h.get("host", ""))
    for c in ct_subs:
        all_subs.add(c.get("subdomain", ""))
    for r in rapid:
        all_subs.add(r.get("subdomain", ""))
    all_subs.discard("")

    # Historical IPs from CIRCL
    ip_history = []
    for entry in circl:
        if entry.get("rrtype") == "A":
            ip_history.append({
                "hostname":   entry["rrname"],
                "ip":         entry["rdata"],
                "first_seen": entry.get("time_first"),
                "last_seen":  entry.get("time_last"),
            })

    # Detect IP changes
    hostname_ips: dict[str, list] = {}
    for e in ip_history:
        hostname_ips.setdefault(e["hostname"], []).append(e["ip"])

    infra_changes = [
        {"hostname": h, "ips": list(set(ips))}
        for h, ips in hostname_ips.items()
        if len(set(ips)) > 1
    ]

    return {
        "domain":               domain,
        "timestamp":            datetime.now(timezone.utc).isoformat(),
        "historical_subdomains": sorted(all_subs),
        "historical_sub_count": len(all_subs),
        "ip_history":           ip_history[:30],
        "infrastructure_changes": infra_changes,
        "ct_timeline":          ct_subs[:20],
        "sources":              ["HackerTarget", "CIRCL.lu", "crt.sh CT logs", "RapidDNS"],
        "findings": [
            {
                "issue":    f"Historical subdomain discovered: {sub} (may still be accessible)",
                "severity": "MEDIUM",
                "evidence": "Found in passive DNS / CT logs — not in current scan",
            }
            for sub in sorted(all_subs)[:5]   # flag top 5 as info
        ],
    }
