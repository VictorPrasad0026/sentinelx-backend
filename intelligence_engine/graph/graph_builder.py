"""
SentinelX Graph Builder

Full graph construction pipeline:
  1. map_profile()            → raw nodes + edges from JSON
  2. deduplicate()            → merge same-entity nodes
  3. discover_relationships() → hidden cross-asset edges
  4. validate_graph()         → integrity check

Single entry: build_graph(profile) -> dict
"""

from intelligence_engine.graph.asset_mapper import map_profile
from intelligence_engine.graph.duplicate_detector import deduplicate
from intelligence_engine.graph.relationship_engine import discover_relationships
from intelligence_engine.graph.graph_validator import validate_graph


def build_graph(profile: dict) -> dict:
    graph = map_profile(profile)
    graph = deduplicate(graph)
    graph = discover_relationships(graph)

    issues = validate_graph(graph)
    graph["validation"] = {
        "passed": len(issues) == 0,
        "issues": issues,
    }
    graph["graph_metadata"] = {
        "engine":  "SentinelX Knowledge Graph Engine v1.0",
        "domain":  profile.get("asset"),
        "version": "1.0",
    }
    return graph
