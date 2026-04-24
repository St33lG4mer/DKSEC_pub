"""Catalog-agnostic comparison engine."""
from __future__ import annotations

from dataclasses import dataclass, field

from core.ast_model import RuleAST


@dataclass
class OverlapPair:
    """A matched pair of rules from catalog A and catalog B."""
    rule_a: RuleAST
    rule_b: RuleAST
    jaccard_score: float
    alert_confirmed: bool = False

    def to_dict(self) -> dict:
        return {
            "rule_a_id": self.rule_a.id,
            "rule_a_name": self.rule_a.name,
            "rule_a_catalog": self.rule_a.catalog,
            "rule_b_id": self.rule_b.id,
            "rule_b_name": self.rule_b.name,
            "rule_b_catalog": self.rule_b.catalog,
            "jaccard_score": self.jaccard_score,
            "alert_confirmed": self.alert_confirmed,
        }


@dataclass
class CompareResult:
    """Output of compare_rules()."""
    overlaps: list[OverlapPair]
    unique_a: list[RuleAST]
    unique_b: list[RuleAST]
    confidence: str            # "full" | "logic-only"
    catalog_a: str
    catalog_b: str

    def to_storage_dicts(self) -> tuple[list[dict], list[dict]]:
        """Return (overlaps_dicts, unique_a_dicts) suitable for ResultStore."""
        return (
            [p.to_dict() for p in self.overlaps],
            [r.to_dict() for r in self.unique_a],
        )
