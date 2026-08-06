"""
SentinelX Duplicate Detector

Merges nodes that represent the same real-world entity
(e.g. two IP nodes with the same address) and rewires edges.
Runs after asset_mapper, before relationship discovery.
"""

from collections import defaultdict


def deduplicate(graph: dict) -> dict:
    nodes = graph["nodes"]
    edges = graph["edges"]

    key_map:    dict[str, str] = {}   # dedup_key → canonical node_id
    id_redirect: dict[str, str] = {}  # old node_id → canonical node_id
    canonical_nodes = []

    for node in nodes:
        nid = node["node_id"]
        key = _make_key(node)
        if key in key_map:
            id_redirect[nid] = key_map[key]   # redirect to canonical
        else:
            key_map[key] = nid
            id_redirect[nid] = nid
            canonical_nodes.append(node)

    # Rewrite edges
    seen_sigs: set = set()
    canonical_edges = []
    for e in edges:
        src = id_redirect.get(e["source_id"], e["source_id"])
        tgt = id_redirect.get(e["target_id"], e["target_id"])
        if src == tgt:
            continue   # self-loop after merge
        sig = (src, tgt, e["rel_type"])
        if sig in seen_sigs:
            continue
        seen_sigs.add(sig)
        canonical_edges.append({**e, "source_id": src, "target_id": tgt})

    graph["nodes"] = canonical_nodes
    graph["edges"] = canonical_edges
    graph.setdefault("statistics", {})
    graph["statistics"]["total_nodes"] = len(canonical_nodes)
    graph["statistics"]["total_edges"] = len(canonical_edges)
    return graph


def _make_key(node: dict) -> str:
    ntype = node.get("node_type", "")
    props = node.get("properties", {})
    name  = node.get("name", "")
    if ntype == "IP":
        return f"IP:{name}"
    if ntype == "Certificate":
        return f"CERT:{name}"
    if ntype == "Technology":
        return f"TECH:{name.lower()}"
    if ntype == "ASN":
        return f"ASN:{props.get('asn', name)}"
    if ntype in ("Cloud", "CDN", "WAF"):
        return f"{ntype}:{name}"
    if ntype in ("Domain", "Subdomain", "Organization"):
        return f"{ntype}:{name}"
    if ntype == "Port":
        return f"PORT:{props.get('port')}:{props.get('service')}"
    # Default: no dedup (findings are always unique)
    return f"{ntype}:{node['node_id']}"
