"""
SentinelX — Canonical Attack Path Registry  v1
FIXED:
  P3 — Single source of truth for attack paths.
       V4 attack_graph_engine and V5 attack_path_generator both import from here.
       No more three independent algorithms producing different counts.

Usage:
  from intelligence_engine.attack_path_canonical import register_paths, get_canonical_paths

  # V4 calls this to register its chains
  register_paths("v4", v4_chains)

  # V5 enriches the same list (does NOT re-generate)
  enrich_paths("v5_cve", cve_data)

  # Everyone reads from one place
  paths = get_canonical_paths()
"""

from datetime import datetime, timezone
from typing import List, Dict

_REGISTRY: Dict[str, list] = {}
_CANONICAL: list = []
_LOCKED = False    # set to True after V5 enrichment — no more additions


def register_paths(source: str, chains: list):
    """
    V4 calls this. Chains are stored under their source label.
    Deduplication is by chain_id.
    """
    global _CANONICAL, _LOCKED
    if _LOCKED:
        return  # V4 must register before V5 enriches

    _REGISTRY[source] = chains
    seen_ids = {c.get("chain_id") for c in _CANONICAL}
    added = 0
    for chain in chains:
        cid = chain.get("chain_id")
        if cid and cid not in seen_ids:
            chain["_source"] = source
            chain["_registered_at"] = datetime.now(timezone.utc).isoformat()
            _CANONICAL.append(chain)
            seen_ids.add(cid)
            added += 1
    print(f"  [Canon] {source}: registered {added} chains ({len(_CANONICAL)} total)")


def enrich_paths(enrichments: list):
    """
    V5 calls this to add CVE/EPSS/KEV/login/secrets data to existing chains.
    Does NOT add new chains independently — only enriches what V4 registered.
    After enrichment, _LOCKED = True.
    """
    global _LOCKED
    enrichment_map = {e.get("chain_id"): e for e in enrichments if e.get("chain_id")}

    for chain in _CANONICAL:
        cid = chain.get("chain_id")
        if cid in enrichment_map:
            chain.update({
                k: v for k, v in enrichment_map[cid].items()
                if k not in ("chain_id", "_source", "_registered_at")
            })
            chain["_enriched"] = True

    # Sort by likelihood desc and assign canonical ranks
    _CANONICAL.sort(key=lambda x: x.get("likelihood", 0), reverse=True)
    for i, c in enumerate(_CANONICAL):
        c["rank"] = i + 1

    _LOCKED = True
    print(f"  [Canon] Enrichment complete. {len(_CANONICAL)} canonical paths. Registry locked.")


def get_canonical_paths() -> list:
    """Single source of truth — everyone calls this."""
    return list(_CANONICAL)


def get_canonical_summary() -> dict:
    paths = _CANONICAL
    critical = [p for p in paths if p.get("likelihood", 0) >= 80]
    kev      = [p for p in paths if p.get("kev_matched")]
    return {
        "total_paths":    len(paths),
        "critical_paths": len(critical),
        "kev_paths":      len(kev),
        "attack_paths":   paths,
        "summary": {
            "top_path":       paths[0]["name"] if paths else None,
            "top_likelihood": paths[0].get("likelihood") if paths else None,
            "source":         "canonical_registry_v1",   # P3: clear provenance
        },
    }


def reset():
    """For testing only."""
    global _CANONICAL, _REGISTRY, _LOCKED
    _CANONICAL = []
    _REGISTRY  = {}
    _LOCKED    = False
