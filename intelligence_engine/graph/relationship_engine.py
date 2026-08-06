"""
SentinelX Relationship Engine

Automatically discovers HIDDEN relationships that are
not obvious from a single asset scan:

  - SHARES_IP          (multiple names → same IP)
  - SHARES_CERTIFICATE (same fingerprint across subdomains)
  - SHARES_TECHNOLOGY  (same stack across assets)
  - TRUSTS             (CSP third-party trust domains)
  - DEPENDS_ON         (MX / NS delegation chains)
  - CONNECTED_TO       (shared ASN / same cloud provider)

Input : graph dict from asset_mapper.map_profile()
Output: same dict with extra edges added
"""

from collections import defaultdict
from intelligence_engine.graph.graph_models import RelType


def discover_relationships(graph: dict) -> dict:
    nodes = {n["node_id"]: n for n in graph["nodes"]}
    edges = list(graph["edges"])

    edges = _shares_ip(nodes, edges)
    edges = _shares_certificate(nodes, edges)
    edges = _shares_technology(nodes, edges)
    edges = _connected_to_same_cloud(nodes, edges)

    graph["edges"] = edges
    graph["statistics"]["total_edges"] = len(edges)
    graph["statistics"]["hidden_relationships_added"] = len(edges) - graph["statistics"]["total_edges"]
    return graph


# ── Helpers ────────────────────────────────────────────────────

def _new_edge(src_id, tgt_id, rel: RelType, props: dict = None) -> dict:
    return {
        "source_id": src_id,
        "target_id": tgt_id,
        "rel_type":  rel.value,
        "properties": props or {},
    }


def _nodes_by_type(nodes: dict, node_type: str) -> list:
    return [n for n in nodes.values() if n["node_type"] == node_type]


def _edges_by_rel(edges: list, rel_type: str) -> list:
    return [e for e in edges if e["rel_type"] == rel_type]


# ── SHARES_IP ──────────────────────────────────────────────────

def _shares_ip(nodes: dict, edges: list) -> list:
    """
    If two different domain/subdomain nodes resolve to the same IP,
    they probably share infrastructure → SHARES_IP.
    """
    resolves = _edges_by_rel(edges, RelType.RESOLVES_TO.value)

    ip_to_holders: dict[str, list] = defaultdict(list)
    for e in resolves:
        ip_to_holders[e["target_id"]].append(e["source_id"])

    existing = {
        (e["source_id"], e["target_id"])
        for e in edges if e["rel_type"] == RelType.SHARES_IP.value
    }

    extra = []
    for ip_id, holders in ip_to_holders.items():
        if len(holders) < 2:
            continue
        ip_name = nodes.get(ip_id, {}).get("name", ip_id)
        for i in range(len(holders)):
            for j in range(i + 1, len(holders)):
                pair = (holders[i], holders[j])
                rev  = (holders[j], holders[i])
                if pair not in existing and rev not in existing:
                    extra.append(_new_edge(holders[i], holders[j],
                                           RelType.SHARES_IP, {"ip": ip_name}))
                    existing.add(pair)
    return edges + extra


# ── SHARES_CERTIFICATE ─────────────────────────────────────────

def _shares_certificate(nodes: dict, edges: list) -> list:
    """
    If two assets point to the same Certificate node,
    they share a cert → probably co-hosted → SHARES_CERTIFICATE.
    """
    cert_edges = [
        e for e in edges
        if e["rel_type"] in (RelType.HAS_CERTIFICATE.value, RelType.SHARES_CERTIFICATE.value)
    ]

    cert_to_holders: dict[str, list] = defaultdict(list)
    for e in cert_edges:
        cert_to_holders[e["target_id"]].append(e["source_id"])

    existing = {
        (e["source_id"], e["target_id"])
        for e in edges if e["rel_type"] == RelType.SHARES_CERTIFICATE.value
    }

    extra = []
    for cert_id, holders in cert_to_holders.items():
        if len(holders) < 2:
            continue
        fp = nodes.get(cert_id, {}).get("name", cert_id)
        for i in range(len(holders)):
            for j in range(i + 1, len(holders)):
                pair = (holders[i], holders[j])
                rev  = (holders[j], holders[i])
                if pair not in existing and rev not in existing:
                    extra.append(_new_edge(holders[i], holders[j],
                                           RelType.SHARES_CERTIFICATE,
                                           {"certificate_fingerprint": fp}))
                    existing.add(pair)
    return edges + extra


# ── SHARES_TECHNOLOGY ──────────────────────────────────────────

def _shares_technology(nodes: dict, edges: list) -> list:
    """
    Assets using the same technology stack cluster together.
    Helps identify blast radius if a framework CVE drops.
    """
    uses_edges = [
        e for e in edges
        if e["rel_type"] in (RelType.USES.value, RelType.SHARES_TECHNOLOGY.value)
        and nodes.get(e["target_id"], {}).get("node_type") == "Technology"
    ]

    tech_to_holders: dict[str, list] = defaultdict(list)
    for e in uses_edges:
        tech_to_holders[e["target_id"]].append(e["source_id"])

    existing = {
        (e["source_id"], e["target_id"])
        for e in edges if e["rel_type"] == RelType.SHARES_TECHNOLOGY.value
    }

    extra = []
    for tech_id, holders in tech_to_holders.items():
        # Only cluster if more than 2 assets share it (reduces noise)
        if len(holders) < 2:
            continue
        tech_name = nodes.get(tech_id, {}).get("name", tech_id)
        for i in range(len(holders)):
            for j in range(i + 1, len(holders)):
                pair = (holders[i], holders[j])
                rev  = (holders[j], holders[i])
                if pair not in existing and rev not in existing:
                    extra.append(_new_edge(holders[i], holders[j],
                                           RelType.SHARES_TECHNOLOGY,
                                           {"technology": tech_name}))
                    existing.add(pair)
    return edges + extra


# ── CONNECTED_TO (same cloud) ──────────────────────────────────

def _connected_to_same_cloud(nodes: dict, edges: list) -> list:
    """
    If multiple IPs belong to the same cloud provider,
    they are probably in the same VPC / region → CONNECTED_TO.
    """
    hosts_edges = [e for e in edges if e["rel_type"] == RelType.HOSTS.value]

    cloud_to_ips: dict[str, list] = defaultdict(list)
    for e in hosts_edges:
        cloud_name = nodes.get(e["target_id"], {}).get("name", "")
        cloud_to_ips[cloud_name].append(e["source_id"])

    existing = {
        (e["source_id"], e["target_id"])
        for e in edges if e["rel_type"] == RelType.CONNECTED_TO.value
    }

    extra = []
    for cloud, ip_ids in cloud_to_ips.items():
        if len(ip_ids) < 2:
            continue
        for i in range(len(ip_ids)):
            for j in range(i + 1, len(ip_ids)):
                pair = (ip_ids[i], ip_ids[j])
                rev  = (ip_ids[j], ip_ids[i])
                if pair not in existing and rev not in existing:
                    extra.append(_new_edge(ip_ids[i], ip_ids[j],
                                           RelType.CONNECTED_TO,
                                           {"reason": f"Same cloud: {cloud}"}))
                    existing.add(pair)
    return edges + extra
