"""
SentinelX Asset Mapper

Parses the flat JSON profile from collectors/asset_profile.py
and converts every object into typed Node + Edge objects.

Single responsibility: JSON → graph objects.
No Neo4j. No attack logic. No business logic.
"""

from intelligence_engine.graph.graph_models import (
    Node, Edge, NodeType, RelType,
)
import uuid


def _node(node_type: NodeType, name: str, props: dict = None) -> Node:
    return Node(node_type=node_type, name=str(name), properties=props or {})


def _edge(src: Node, tgt: Node, rel: RelType, props: dict = None) -> Edge:
    return Edge(source_id=src.node_id, target_id=tgt.node_id,
                rel_type=rel, properties=props or {})


def map_profile(profile: dict) -> dict:
    """
    Input : raw profile dict from generate_asset_profile()
    Output: { "nodes": [...], "edges": [...] }
    """
    nodes: list[Node] = []
    edges: list[Edge] = []

    domain = profile.get("asset", "unknown")

    # ── Organization ───────────────────────────────────────────
    org = _node(NodeType.ORGANIZATION, domain)
    nodes.append(org)

    # ── Domain ─────────────────────────────────────────────────
    dom_intel = profile.get("domain_intelligence", {})
    dom = _node(NodeType.DOMAIN, domain, {
        "registrar":  dom_intel.get("whois", {}).get("registrar"),
        "created":    dom_intel.get("whois", {}).get("created"),
        "expires":    dom_intel.get("whois", {}).get("expires"),
        "dnssec":     dom_intel.get("dnssec"),
        "reputation": dom_intel.get("reputation", {}),
    })
    nodes.append(dom)
    edges.append(_edge(org, dom, RelType.OWNS))

    # ── DNS IPs ────────────────────────────────────────────────
    dns = profile.get("dns_intelligence", {})
    ip_nodes: dict[str, Node] = {}   # ip → Node (dedup)

    for ip in dns.get("A", []):
        if ip not in ip_nodes:
            n = _node(NodeType.IP, ip, {"version": "IPv4"})
            nodes.append(n)
            ip_nodes[ip] = n
        edges.append(_edge(dom, ip_nodes[ip], RelType.RESOLVES_TO))

    for ip in dns.get("AAAA", []):
        if ip not in ip_nodes:
            n = _node(NodeType.IP, ip, {"version": "IPv6"})
            nodes.append(n)
            ip_nodes[ip] = n
        edges.append(_edge(dom, ip_nodes[ip], RelType.RESOLVES_TO))

    # ── SSL Certificate ────────────────────────────────────────
    ssl_intel = profile.get("ssl_intelligence", {}).get("ssl", {})
    cert_node = None
    if ssl_intel and ssl_intel.get("status") not in (None, "FAILED"):
        fp = ssl_intel.get("fingerprint_sha256", str(uuid.uuid4()))
        cert_node = _node(NodeType.CERTIFICATE, fp, {
            "issuer":       ssl_intel.get("issuer"),
            "san":          ssl_intel.get("san", []),
            "valid_until":  ssl_intel.get("valid_until"),
            "tls_version":  ssl_intel.get("tls_version"),
            "wildcard":     ssl_intel.get("wildcard"),
            "days_remaining": ssl_intel.get("days_remaining"),
            "status":       ssl_intel.get("status"),
        })
        nodes.append(cert_node)
        edges.append(_edge(dom, cert_node, RelType.HAS_CERTIFICATE))

    # ── Infrastructure (ASN / Cloud / CDN / Ports) ─────────────
    infra = profile.get("infrastructure_intelligence", {})
    main_ip = infra.get("ip")

    asn_data = infra.get("asn", {})
    if isinstance(asn_data, dict) and asn_data.get("asn"):
        asn_node = _node(NodeType.ASN, asn_data["asn"], {
            "description": asn_data.get("description"),
            "country":     asn_data.get("country"),
            "registry":    asn_data.get("registry"),
        })
        nodes.append(asn_node)
        if main_ip and main_ip in ip_nodes:
            edges.append(_edge(ip_nodes[main_ip], asn_node, RelType.PART_OF))

    cloud_data = infra.get("cloud", {})
    if isinstance(cloud_data, dict) and cloud_data.get("provider", "UNKNOWN") != "UNKNOWN":
        cloud_node = _node(NodeType.CLOUD, cloud_data["provider"], {
            "confidence": cloud_data.get("confidence"),
            "evidence":   cloud_data.get("evidence", []),
        })
        nodes.append(cloud_node)
        if main_ip and main_ip in ip_nodes:
            edges.append(_edge(ip_nodes[main_ip], cloud_node, RelType.HOSTS))

    cdn_data = infra.get("cdn", {})
    if isinstance(cdn_data, dict) and cdn_data.get("detected"):
        cdn_node = _node(NodeType.CDN, cdn_data.get("provider", "Unknown CDN"), {
            "confidence": cdn_data.get("confidence"),
            "evidence":   cdn_data.get("evidence", []),
        })
        nodes.append(cdn_node)
        edges.append(_edge(dom, cdn_node, RelType.PROTECTED_BY))

    port_nodes: dict[int, Node] = {}
    for p in infra.get("ports", {}).get("ports", []):
        if p.get("state") == "OPEN":
            pn = _node(NodeType.PORT, str(p["port"]), {
                "port":    p["port"],
                "service": p.get("service"),
                "risk":    p.get("risk"),
                "banner":  p.get("banner"),
            })
            nodes.append(pn)
            port_nodes[p["port"]] = pn
            if main_ip and main_ip in ip_nodes:
                edges.append(_edge(ip_nodes[main_ip], pn, RelType.HAS_PORT))

    # ── WAF ────────────────────────────────────────────────────
    http_intel = profile.get("http_intelligence", {})
    waf = http_intel.get("waf", {})
    if isinstance(waf, dict) and waf.get("detected"):
        waf_node = _node(NodeType.WAF, waf.get("provider", "Unknown WAF"))
        nodes.append(waf_node)
        edges.append(_edge(dom, waf_node, RelType.PROTECTED_BY))

    # ── Technologies ───────────────────────────────────────────
    tech_intel = profile.get("technology_intelligence", {})
    tech_nodes: dict[str, Node] = {}
    for t in tech_intel.get("technology", {}).get("detected_frameworks", []):
        name = t["name"] if isinstance(t, dict) else str(t)
        if name not in tech_nodes:
            tn = _node(NodeType.TECHNOLOGY, name, {
                "evidence": t.get("evidence") if isinstance(t, dict) else None
            })
            nodes.append(tn)
            tech_nodes[name] = tn
        edges.append(_edge(dom, tech_nodes[name], RelType.USES))

    # ── Email System ───────────────────────────────────────────
    email_intel = profile.get("email_intelligence", {})
    if email_intel and not email_intel.get("error"):
        em_node = _node(NodeType.EMAIL_SYSTEM, domain, {
            "provider": email_intel.get("mx", {}).get("provider"),
            "spf":      email_intel.get("spf", {}),
            "dmarc":    email_intel.get("dmarc", {}),
            "dkim":     email_intel.get("dkim", {}),
        })
        nodes.append(em_node)
        edges.append(_edge(dom, em_node, RelType.USES))

    # ── Risk Findings (domain-level) ───────────────────────────
    risk = profile.get("risk_assessment", {})
    for f in risk.get("findings", []):
        fn = _node(NodeType.FINDING, f.get("issue", "Unknown"), {
            "category":       f.get("category"),
            "severity":       f.get("severity"),
            "score":          f.get("score", 0),
            "recommendation": f.get("recommendation", ""),
        })
        nodes.append(fn)
        edges.append(_edge(dom, fn, RelType.HAS_FINDING))

    # ── Subdomains ─────────────────────────────────────────────
    sub_assets = profile.get("subdomain_assets", {}).get("assets", [])
    cert_fingerprints: dict[str, Node] = {}
    if cert_node:
        fp_key = ssl_intel.get("fingerprint_sha256", "")
        if fp_key:
            cert_fingerprints[fp_key] = cert_node

    for asset in sub_assets:
        host = asset.get("host", "")
        asset_risk = asset.get("risk", {})
        sub = _node(NodeType.SUBDOMAIN, host, {
            "risk_score":    asset_risk.get("score", 0),
            "risk_severity": asset_risk.get("severity", "UNKNOWN"),
            "sources":       asset.get("sources", [asset.get("source")]),
        })
        nodes.append(sub)
        edges.append(_edge(dom, sub, RelType.HAS_SUBDOMAIN))

        # Sub IPs
        for ip in asset.get("dns", {}).get("A", []):
            if ip not in ip_nodes:
                n = _node(NodeType.IP, ip, {"version": "IPv4"})
                nodes.append(n)
                ip_nodes[ip] = n
            edges.append(_edge(sub, ip_nodes[ip], RelType.RESOLVES_TO))

        # Sub certificate
        sub_ssl = asset.get("ssl", {})
        sub_fp = sub_ssl.get("fingerprint_sha256") or sub_ssl.get("ssl", {}).get("fingerprint_sha256")
        if sub_fp:
            if sub_fp in cert_fingerprints:
                # SHARES_CERTIFICATE relationship
                edges.append(_edge(sub, cert_fingerprints[sub_fp], RelType.SHARES_CERTIFICATE))
            else:
                scn = _node(NodeType.CERTIFICATE, sub_fp, {
                    "tls_version": sub_ssl.get("tls_version") or sub_ssl.get("ssl", {}).get("tls_version"),
                    "status":      sub_ssl.get("status") or sub_ssl.get("ssl", {}).get("status"),
                })
                nodes.append(scn)
                cert_fingerprints[sub_fp] = scn
                edges.append(_edge(sub, scn, RelType.HAS_CERTIFICATE))

        # Sub technologies
        for t in asset.get("http", {}).get("technologies", []):
            name = t["name"] if isinstance(t, dict) else str(t)
            if name not in tech_nodes:
                tn = _node(NodeType.TECHNOLOGY, name, {
                    "evidence": t.get("evidence") if isinstance(t, dict) else None
                })
                nodes.append(tn)
                tech_nodes[name] = tn
                edges.append(_edge(dom, tn, RelType.USES))
            edges.append(_edge(sub, tech_nodes[name], RelType.SHARES_TECHNOLOGY))

        # Sub ports — from asset.infrastructure.ports.ports[]
        sub_infra = asset.get("infrastructure", {})
        sub_ports_data = sub_infra.get("ports", {})
        if isinstance(sub_ports_data, dict):
            sub_open_ports = sub_ports_data.get("ports", [])
        else:
            sub_open_ports = []
        for p in sub_open_ports:
            if p.get("state", "OPEN") != "OPEN":
                continue
            port_key = f"{host}:{p['port']}"
            if port_key not in port_nodes:
                pn = _node(NodeType.PORT, str(p["port"]), {
                    "port":    p["port"],
                    "service": p.get("service"),
                    "risk":    p.get("risk"),
                    "banner":  p.get("banner"),
                    "host":    host,
                })
                nodes.append(pn)
                port_nodes[port_key] = pn
            edges.append(_edge(sub, port_nodes[port_key], RelType.HAS_PORT))

        # Sub findings
        for f in asset_risk.get("findings", []):
            fn = _node(NodeType.FINDING, f.get("issue", "Unknown"), {
                "category": f.get("category", "Asset"),
                "severity": f.get("severity"),
                "score":    f.get("score", 0),
            })
            nodes.append(fn)
            edges.append(_edge(sub, fn, RelType.HAS_FINDING))

    # ── SHARES_IP (cross-asset) ────────────────────────────────
    # Build ip → [node_ids] map then add SHARES_IP between holders
    ip_to_assets: dict[str, list] = {}
    for e in edges:
        if e.rel_type == RelType.RESOLVES_TO:
            ip_to_assets.setdefault(e.target_id, []).append(e.source_id)
    for ip_id, holders in ip_to_assets.items():
        if len(holders) > 1:
            for i in range(len(holders)):
                for j in range(i + 1, len(holders)):
                    edges.append(Edge(
                        source_id=holders[i],
                        target_id=holders[j],
                        rel_type=RelType.SHARES_IP,
                        properties={"shared_ip_node": ip_id},
                    ))

    return {
        "nodes": [n.to_dict() for n in nodes],
        "edges": [e.to_dict() for e in edges],
        "statistics": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "node_types":  _count_types(nodes),
        },
    }


def _count_types(nodes: list) -> dict:
    counts: dict[str, int] = {}
    for n in nodes:
        t = n.node_type.value
        counts[t] = counts.get(t, 0) + 1
    return counts
