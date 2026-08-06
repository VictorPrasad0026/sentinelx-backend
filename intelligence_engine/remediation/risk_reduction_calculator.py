"""
SentinelX Risk Reduction Calculator

Estimates risk score reduction if all findings are fixed.
"""

from typing import Dict, Any, List

SEVERITY_REDUCTION = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5, "INFO": 1}


class RiskReductionCalculator:

    def calculate(self, findings: List[Dict], prioritized: List[Dict]) -> Dict[str, Any]:
        max_reduction = min(sum(SEVERITY_REDUCTION.get(f.get("severity", "INFO"), 1)
                                for f in findings), 100)
        quick_win_reduction = min(sum(f.get("risk_reduction", 0)
                                      for f in prioritized if f.get("estimated_hours", 99) <= 2), 100)
        return {
            "current_risk_score": self._current_score(findings),
            "max_reduction": max_reduction,
            "quick_win_reduction": quick_win_reduction,
            "projected_score_after_quick_wins": max(0, self._current_score(findings) - quick_win_reduction),
            "projected_score_after_all_fixes": max(0, self._current_score(findings) - max_reduction)
        }

    def _current_score(self, findings: List[Dict]) -> int:
        return min(sum(f.get("score", 0) for f in findings), 100)
