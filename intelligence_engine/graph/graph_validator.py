"""
SentinelX Graph Validator

Checks graph integrity:
  - No dangling edge references
  - No duplicate node IDs
  - Every edge has a valid rel_type
"""

from intelligence_engine.graph.graph_models import RelType


def validate_graph(graph: dict) -> list[str]:
    issues = []
    node_ids = {n["node_id"] for n in graph["nodes"]}
    seen_ids: set = set()
    valid_rels = {r.value for r in RelType}

    for n in graph["nodes"]:
        if n["node_id"] in seen_ids:
            issues.append(f"Duplicate node_id: {n['node_id']}")
        seen_ids.add(n["node_id"])

    for e in graph["edges"]:
        if e["source_id"] not in node_ids:
            issues.append(f"Dangling source: {e['source_id']}")
        if e["target_id"] not in node_ids:
            issues.append(f"Dangling target: {e['target_id']}")
        if e["rel_type"] not in valid_rels:
            issues.append(f"Unknown rel_type: {e['rel_type']}")

    return issues
