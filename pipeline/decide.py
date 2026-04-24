"""
Produce ADD / SKIP decisions for rules in catalog A based on comparison results.

ADD  — rule has no confirmed overlap in catalog B (add to SIEM)
SKIP — rule overlaps with at least one rule in catalog B (already covered)
"""
from __future__ import annotations

from pipeline.compare import CompareResult


def decide(result: CompareResult) -> dict[str, str]:
    """
    Return a decision for every rule in catalog A.

    Returns:
        dict mapping rule_id → "ADD" | "SKIP"
    """
    decisions: dict[str, str] = {}

    for rule in result.unique_a:
        decisions[rule.id] = "ADD"

    for pair in result.overlaps:
        decisions[pair.rule_a.id] = "SKIP"

    return decisions
