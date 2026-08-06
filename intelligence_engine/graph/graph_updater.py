"""
SentinelX Graph Updater

Merges a new scan's graph into an existing snapshot.
Detects: new nodes, removed nodes, changed properties.
Used by the timeline engine to track infrastructure changes.
"""


def compute_diff(existing_graph: dict, incoming_graph: dict) -> dict:
    existing = {n["node_id"]: n for n in existing_graph.get("nodes", [])}
    incoming = {n["node_id"]: n for n in incoming_graph.get("nodes", [])}

    existing_keys = set(existing)
    incoming_keys = set(incoming)

    added   = [incoming[k] for k in incoming_keys - existing_keys]
    removed = [existing[k] for k in existing_keys - incoming_keys]
    changed = []

    for k in existing_keys & incoming_keys:
        old = existing[k].get("properties", {})
        new = incoming[k].get("properties", {})
        all_keys = set(list(old) + list(new))
        diffs = {
            fk: {"old": old.get(fk), "new": new.get(fk)}
            for fk in all_keys
            if old.get(fk) != new.get(fk)
        }
        if diffs:
            changed.append({
                "node_id": k,
                "name":    incoming[k].get("name"),
                "changes": diffs,
            })

    return {
        "added_nodes":    len(added),
        "removed_nodes":  len(removed),
        "changed_nodes":  len(changed),
        "new_assets":     [n.get("name") for n in added],
        "removed_assets": [n.get("name") for n in removed],
        "changes":        changed[:50],
    }
