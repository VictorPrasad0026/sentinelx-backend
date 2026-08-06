"""
SentinelX Snapshot Manager

Saves every scan as a versioned snapshot.
Enables change detection and trend analysis.
Storage: JSON files per domain per timestamp.
(Designed to be backed by MongoDB in production.)
"""

import os
import json
from datetime import datetime, timezone


SNAPSHOT_DIR = "snapshots"


def save_snapshot(domain: str, intelligence_report: dict) -> str:
    os.makedirs(SNAPSHOT_DIR, exist_ok=True)
    domain_dir = os.path.join(SNAPSHOT_DIR, domain.replace(".", "_"))
    os.makedirs(domain_dir, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"{ts}.json"
    path = os.path.join(domain_dir, filename)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(intelligence_report, f, indent=2, default=str)

    return path


def load_snapshots(domain: str) -> list[dict]:
    domain_dir = os.path.join(SNAPSHOT_DIR, domain.replace(".", "_"))
    if not os.path.exists(domain_dir):
        return []

    snapshots = []
    for fname in sorted(os.listdir(domain_dir)):
        if fname.endswith(".json"):
            with open(os.path.join(domain_dir, fname), encoding="utf-8") as f:
                try:
                    snapshots.append(json.load(f))
                except Exception:
                    pass
    return snapshots


def latest_snapshot(domain: str) -> dict | None:
    snaps = load_snapshots(domain)
    return snaps[-1] if snaps else None


def previous_snapshot(domain: str) -> dict | None:
    snaps = load_snapshots(domain)
    return snaps[-2] if len(snaps) >= 2 else None
