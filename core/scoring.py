# core/scoring.py
"""Rule scoring and classification — extracted from utils.py."""
from __future__ import annotations

from core.ast_model import RuleAST
from core.normalizer import SEVERITY_TO_RISK


def score_rule(
    rule: RuleAST,
    has_overlap: bool,
    alert_fires: int,
) -> int:
    """
    Compute a raw composite score for a rule.

    Formula (same as original utils.py):
        risk_score
        + 10  if translated_query is not None (valid EQL)
        + 5   x number of MITRE techniques
        - 15  if has_overlap (duplicate coverage)
        + min(alert_fires x 2, 20)  (capped alert bonus)
    """
    risk = SEVERITY_TO_RISK.get(rule.severity, 47)
    valid_eql_bonus = 10 if rule.translated_query is not None else 0
    technique_bonus = 5 * len(rule.mitre_techniques)
    overlap_penalty = -15 if has_overlap else 0
    alert_bonus = min(alert_fires * 2, 20)
    return risk + valid_eql_bonus + technique_bonus + overlap_penalty + alert_bonus


def normalize_scores(raw_scores: list[int]) -> list[float]:
    """
    Min-max normalize a list of raw scores to the range [0, 100].
    If all scores are identical, returns 50.0 for each to avoid divide-by-zero.
    """
    if not raw_scores:
        return []
    mn = min(raw_scores)
    mx = max(raw_scores)
    if mx == mn:
        return [50.0] * len(raw_scores)
    return [(s - mn) / (mx - mn) * 100 for s in raw_scores]


def classify_rule(alert_fires: int, severity: str) -> str:
    """
    Classify a rule into one of four operational categories.

    dead     -- never fired in 24h
    noisy    -- 50+ fires, low or medium severity (likely false positive)
    valuable -- any fires, high or critical severity
    active   -- fired but doesn't meet noisy or valuable criteria
    """
    if alert_fires == 0:
        return "dead"
    if alert_fires >= 50 and severity in ("low", "medium"):
        return "noisy"
    if severity in ("high", "critical"):
        return "valuable"
    return "active"
