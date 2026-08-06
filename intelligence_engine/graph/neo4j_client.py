"""
SentinelX Neo4j Client

Writes the in-memory graph to Neo4j when available.
Falls back gracefully if Neo4j is not installed or not running.

Isolated from all other modules — swap this for any graph DB later.
"""

from datetime import datetime, timezone

try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False


class Neo4jClient:

    def __init__(self, uri: str = "bolt://localhost:7687",
                 user: str = "neo4j", password: str = "password"):
        self.uri = uri
        self.user = user
        self.password = password
        self.driver = None
        self.available = False

        if not NEO4J_AVAILABLE:
            return
        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            self.driver.verify_connectivity()
            self.available = True
        except Exception:
            self.available = False

    def close(self):
        if self.driver:
            self.driver.close()

    def write_graph(self, graph: dict, domain: str) -> dict:
        if not self.available:
            return {
                "status": "SKIPPED",
                "reason": "Neo4j not available (driver not installed or server not running)",
                "tip":    "pip install neo4j && start Neo4j Desktop or Docker",
            }

        nodes_written = 0
        edges_written = 0

        with self.driver.session() as session:
            # Write nodes
            for node in graph["nodes"]:
                session.run(
                    """
                    MERGE (n {node_id: $node_id})
                    SET n += $properties
                    SET n.node_type = $node_type
                    SET n.name = $name
                    SET n.domain = $domain
                    SET n.updated_at = $ts
                    """,
                    node_id=node["node_id"],
                    node_type=node["node_type"],
                    name=node["name"],
                    domain=domain,
                    ts=datetime.now(timezone.utc).isoformat(),
                    properties={
                        k: str(v) if isinstance(v, (dict, list)) else v
                        for k, v in node.get("properties", {}).items()
                        if v is not None
                    },
                )
                nodes_written += 1

            # Write edges
            for edge in graph["edges"]:
                cypher = f"""
                    MATCH (a {{node_id: $src}})
                    MATCH (b {{node_id: $tgt}})
                    MERGE (a)-[r:{edge['rel_type']}]->(b)
                    SET r += $properties
                """
                session.run(
                    cypher,
                    src=edge["source_id"],
                    tgt=edge["target_id"],
                    properties=edge.get("properties", {}),
                )
                edges_written += 1

        return {
            "status":        "SUCCESS",
            "nodes_written": nodes_written,
            "edges_written": edges_written,
            "uri":           self.uri,
        }

    def clear_domain(self, domain: str):
        """Remove all nodes for a domain (for re-scan)."""
        if not self.available:
            return
        with self.driver.session() as session:
            session.run("MATCH (n {domain: $domain}) DETACH DELETE n", domain=domain)
