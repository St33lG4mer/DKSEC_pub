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


# ---------------------------------------------------------------------------
# compare_rules() implementation
# ---------------------------------------------------------------------------

from core.normalizer import extract_eql_tokens, jaccard


def _tokens_for(rule: RuleAST) -> frozenset:
    """Extract tokens. Prefer translated_query; fall back to raw_query."""
    query = rule.translated_query if rule.translated_query is not None else rule.raw_query
    return extract_eql_tokens(query)


def _should_compare(rule_a: RuleAST, rule_b: RuleAST, tokens_a: frozenset, tokens_b: frozenset) -> bool:
    """
    Pre-filter: only compute Jaccard if rules share at least one MITRE technique
    or their token sets have a non-empty intersection.
    """
    if rule_a.mitre_techniques and rule_b.mitre_techniques:
        if set(rule_a.mitre_techniques) & set(rule_b.mitre_techniques):
            return True
    return bool(tokens_a & tokens_b)


def compare_rules(
    rules_a: list[RuleAST],
    rules_b: list[RuleAST],
    alerts: list[dict] | None = None,
    threshold: float = 0.40,
) -> CompareResult:
    """
    Compare two rule sets and return overlaps + unique rules.

    For each rule in catalog A, at most one best-matching rule in catalog B
    is recorded as an overlap (highest Jaccard score >= threshold wins).
    This prevents N×M inflation where one rule matches many counterparts.

    Logic-only mode (alerts=None):
        - Extract tokens from each rule (translated_query preferred)
        - Pre-filter by shared tokens or MITRE techniques
        - For each rule_a, pick best rule_b by Jaccard; pair >= threshold → overlap
        - confidence = "logic-only"

    Full mode (alerts provided):
        - Same logic pass
        - Additionally mark pairs as alert_confirmed if both rules fired on same scenario
        - A pair is an overlap if EITHER signal confirms it
        - confidence = "full"
    """
    if not rules_a or not rules_b:
        catalog_a = rules_a[0].catalog if rules_a else (rules_b[0].catalog if rules_b else "")
        catalog_b = rules_b[0].catalog if rules_b else (rules_a[0].catalog if rules_a else "")
        return CompareResult(
            overlaps=[],
            unique_a=list(rules_a),
            unique_b=list(rules_b),
            confidence="logic-only" if alerts is None else "full",
            catalog_a=catalog_a,
            catalog_b=catalog_b,
        )

    catalog_a = rules_a[0].catalog
    catalog_b = rules_b[0].catalog

    # Pre-compute tokens
    tokens_a = {r.id: _tokens_for(r) for r in rules_a}
    tokens_b = {r.id: _tokens_for(r) for r in rules_b}
    rules_b_by_id = {r.id: r for r in rules_b}

    # Build alert co-firing index: scenario_id → set of rule_ids that fired
    scenario_to_rules: dict[str, set[str]] = {}
    if alerts:
        for alert in alerts:
            scenario_id = alert.get("scenario_id", "")
            rule_id = alert.get("rule_id", "")
            if scenario_id and rule_id:
                scenario_to_rules.setdefault(scenario_id, set()).add(rule_id)

    overlap_pairs: list[OverlapPair] = []
    overlapped_a_ids: set[str] = set()
    overlapped_b_ids: set[str] = set()

    for a in rules_a:
        ta = tokens_a[a.id]

        # Find best-matching rule_b for this rule_a
        best_score = 0.0
        best_b: RuleAST | None = None
        alert_confirmed_for_best = False

        for b in rules_b:
            tb = tokens_b[b.id]

            score = 0.0
            if _should_compare(a, b, ta, tb):
                score = jaccard(ta, tb)

            # Check alert co-firing
            alert_confirmed = False
            if alerts is not None:
                for fired_ids in scenario_to_rules.values():
                    if a.id in fired_ids and b.id in fired_ids:
                        alert_confirmed = True
                        break

            # Update best match: alert confirmation overrides logic score
            if alert_confirmed and not alert_confirmed_for_best:
                best_score = score
                best_b = b
                alert_confirmed_for_best = True
            elif alert_confirmed and alert_confirmed_for_best and score > best_score:
                best_score = score
                best_b = b
            elif not alert_confirmed_for_best and score > best_score:
                best_score = score
                best_b = b

        if best_b is not None and (best_score >= threshold or alert_confirmed_for_best):
            overlap_pairs.append(
                OverlapPair(
                    rule_a=a,
                    rule_b=best_b,
                    jaccard_score=best_score,
                    alert_confirmed=alert_confirmed_for_best,
                )
            )
            overlapped_a_ids.add(a.id)
            overlapped_b_ids.add(best_b.id)

    unique_a = [r for r in rules_a if r.id not in overlapped_a_ids]
    unique_b = [r for r in rules_b if r.id not in overlapped_b_ids]
    confidence = "logic-only" if alerts is None else "full"

    return CompareResult(
        overlaps=overlap_pairs,
        unique_a=unique_a,
        unique_b=unique_b,
        confidence=confidence,
        catalog_a=catalog_a,
        catalog_b=catalog_b,
    )
