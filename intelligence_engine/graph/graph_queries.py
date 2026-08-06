"""
SentinelX Graph Queries

Pure Python graph traversal over the in-memory dict graph.
No Neo4j required. Designed to be swapped for Cypher later.
"""

from collections import defaultdict


class GraphQuery:
    def __init__(self, graph: dict):
        self.nodes = {n["node_id"]: n for n in graph["nodes"]}
        self.edges = graph["edges"]
        self._out = defaultdict(list)   # source_id → [edges]
        self._in  = defaultdict(list)   # target_id → [edges]
        for e in self.edges:
            self._out[e["source_id"]].append(e)
            self._in[e["target_id"]].append(e)

    def neighbors(self, node_id: str, rel_type: str = None) -> list[dict]:
        edges = self._out.get(node_id, [])
        if rel_type:
            edges = [e for e in edges if e["rel_type"] == rel_type]
        return [self.nodes[e["target_id"]] for e in edges if e["target_id"] in self.nodes]

    def by_type(self, node_type: str) -> list[dict]:
        return [n for n in self.nodes.values() if n["node_type"] == node_type]

    def find_shared_ips(self) -> list[dict]:
        return [e for e in self.edges if e["rel_type"] == "SHARES_IP"]

    def find_shared_certs(self) -> list[dict]:
        return [e for e in self.edges if e["rel_type"] == "SHARES_CERTIFICATE"]

    def internet_facing_assets(self) -> list[dict]:
        """Assets with open ports or direct IP resolution."""
        return [
            self.nodes[e["source_id"]]
            for e in self.edges
            if e["rel_type"] == "HAS_PORT"
            and e["source_id"] in self.nodes
        ]

    def all_findings(self, severity: str = None) -> list[dict]:
        findings = self.by_type("Finding")
        if severity:
            findings = [f for f in findings
                        if f["properties"].get("severity") == severity]
        return findings

    def assets_using_technology(self, tech_name: str) -> list[dict]:
        tech = next((n for n in self.by_type("Technology")
                     if n["name"].lower() == tech_name.lower()), None)
        if not tech:
            return []
        in_edges = self._in.get(tech["node_id"], [])
        return [self.nodes[e["source_id"]] for e in in_edges
                if e["source_id"] in self.nodes]

    def path_exists(self, src_id: str, tgt_id: str, max_depth: int = 5) -> bool:
        """BFS to check if a path exists between two nodes."""
        visited = set()
        queue = [src_id]
        for _ in range(max_depth):
            next_q = []
            for nid in queue:
                if nid == tgt_id:
                    return True
                if nid in visited:
                    continue
                visited.add(nid)
                for e in self._out.get(nid, []):
                    next_q.append(e["target_id"])
            queue = next_q
        return False
