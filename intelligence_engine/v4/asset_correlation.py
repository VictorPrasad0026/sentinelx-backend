"""
SentinelX V4 — Asset Correlation Engine

Groups all findings by the ASSET they belong to, not by category.

Before: 10 separate findings scattered across modules
After:  Each asset owns its findings, IPs, certs, tech, risk

Correlation keys:
  - IP address (SHARES_IP)
  - SSL certificate fingerprint (SHARES_CERTIFICATE)
  - ASN (CONNECTED_TO)
  - Cloud provider (SAME_CLOUD)
  - Technology stack (SHARES_TECHNOLOGY)
  - Organization / WHOIS (SAME_ORG)
"""

from collections import defaultdict


def correlate_assets(profile: dict) -> dict:
    """
    Returns a dict where every asset is fully correlated with:
    - All findings that belong to it
    - Other assets it shares infrastructure with
    - Its complete exposure picture
    """

    assets = profile.get("subdomain_assets", {}).get("assets", [])
    domain_risk = profile.get("risk_assessment", {})
    domain_findings = domain_risk.get("findings", [])

    # ── Build per-asset records ──────────────────────────────
    asset_map: dict[str, dict] = {}

    for asset in assets:
        host = asset["host"]
        infra = asset.get("infrastructure", {})
        ip = infra.get("ip")
        ports = [p for p in infra.get("ports", {}).get("ports", [])
                 if p.get("state") == "OPEN"]
        ssl_data = asset.get("ssl", {})
        ssl_fp = ssl_data.get("fingerprint_sha256")
        asn = infra.get("asn", {})
        asn_num = asn.get("asn") if isinstance(asn, dict) else None
        cloud = infra.get("cloud", {})
        cloud_provider = (cloud.get("provider") if isinstance(cloud, dict) else cloud) or "UNKNOWN"
        techs = [t["name"] if isinstance(t, dict) else t
                 for t in asset.get("http", {}).get("technologies", [])]
        asset_findings = asset.get("risk", {}).get("findings", [])

        asset_map[host] = {
            "host":             host,
            "ip":               ip,
            "asn":              asn_num,
            "cloud":            cloud_provider,
            "ssl_fingerprint":  ssl_fp,
            "open_ports":       [p["port"] for p in ports],
            "services":         [p.get("service") for p in ports],
            "technologies":     techs,
            "findings":         asset_findings,
            "risk_score":       asset.get("risk", {}).get("score", 0),
            "risk_severity":    asset.get("risk", {}).get("severity", "UNKNOWN"),
            "shares_ip_with":   [],
            "shares_cert_with": [],
            "shares_tech_with": defaultdict(list),
            "same_cloud_as":    [],
            "exposure_score":   infra.get("exposure_score", 0),
        }

    # ── IP clustering ────────────────────────────────────────
    ip_to_hosts: dict[str, list] = defaultdict(list)
    for host, data in asset_map.items():
        if data["ip"]:
            ip_to_hosts[data["ip"]].append(host)

    for ip, hosts in ip_to_hosts.items():
        if len(hosts) > 1:
            for host in hosts:
                asset_map[host]["shares_ip_with"] = [
                    h for h in hosts if h != host
                ]

    # ── Certificate clustering ───────────────────────────────
    fp_to_hosts: dict[str, list] = defaultdict(list)
    for host, data in asset_map.items():
        if data["ssl_fingerprint"]:
            fp_to_hosts[data["ssl_fingerprint"]].append(host)

    for fp, hosts in fp_to_hosts.items():
        if len(hosts) > 1:
            for host in hosts:
                asset_map[host]["shares_cert_with"] = [
                    h for h in hosts if h != host
                ]

    # ── Technology clustering ────────────────────────────────
    tech_to_hosts: dict[str, list] = defaultdict(list)
    for host, data in asset_map.items():
        for tech in data["technologies"]:
            tech_to_hosts[tech].append(host)

    for tech, hosts in tech_to_hosts.items():
        if len(hosts) > 1:
            for host in hosts:
                peers = [h for h in hosts if h != host]
                asset_map[host]["shares_tech_with"][tech] = peers

    # ── Cloud clustering ─────────────────────────────────────
    cloud_to_hosts: dict[str, list] = defaultdict(list)
    for host, data in asset_map.items():
        if data["cloud"] and data["cloud"] != "UNKNOWN":
            cloud_to_hosts[data["cloud"]].append(host)

    for cloud, hosts in cloud_to_hosts.items():
        if len(hosts) > 1:
            for host in hosts:
                asset_map[host]["same_cloud_as"] = [
                    h for h in hosts if h != host
                ]

    # ── Assign domain-level findings to domain ───────────────
    domain = profile.get("asset", "unknown")

    # ── Convert defaultdicts for JSON serialisation ──────────
    for host in asset_map:
        asset_map[host]["shares_tech_with"] = dict(
            asset_map[host]["shares_tech_with"]
        )

    # ── Summary ──────────────────────────────────────────────
    ip_clusters = {ip: hosts for ip, hosts in ip_to_hosts.items() if len(hosts) > 1}
    cert_clusters = {fp[:16]: hosts for fp, hosts in fp_to_hosts.items() if len(hosts) > 1}

    return {
        "domain":        domain,
        "total_assets":  len(asset_map),
        "ip_clusters":   ip_clusters,
        "cert_clusters": cert_clusters,
        "cloud_clusters": {k: v for k, v in cloud_to_hosts.items() if len(v) > 1},
        "assets":        list(asset_map.values()),
        "domain_findings": domain_findings,
    }
