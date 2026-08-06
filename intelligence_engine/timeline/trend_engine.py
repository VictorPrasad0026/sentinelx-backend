"""
SentinelX Trend Engine

Analyzes historical snapshots to produce trend reports.
"""

from typing import List, Dict, Any


class TrendEngine:

    def analyze(self, snapshots: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not snapshots:
            return {"error": "No snapshots available"}

        scores = [s.get("risk_assessment", {}).get("risk_score", 0) for s in snapshots]
        subdomain_counts = [
            s.get("attack_surface", {}).get("total_subdomains", 0) for s in snapshots
        ]

        return {
            "snapshot_count": len(snapshots),
            "risk_score_history": scores,
            "risk_score_trend": self._trend(scores),
            "subdomain_count_history": subdomain_counts,
            "subdomain_trend": self._trend(subdomain_counts),
            "average_risk_score": round(sum(scores) / len(scores), 1),
            "peak_risk_score": max(scores),
            "current_risk_score": scores[-1] if scores else 0
        }

    def _trend(self, values: List[int]) -> str:
        if len(values) < 2:
            return "INSUFFICIENT_DATA"
        delta = values[-1] - values[0]
        if delta > 5:
            return "WORSENING"
        if delta < -5:
            return "IMPROVING"
        return "STABLE"
