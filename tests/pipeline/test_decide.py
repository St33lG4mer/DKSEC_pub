"""Tests for decide()."""
import pytest
from core.ast_model import RuleAST
from pipeline.compare import CompareResult, OverlapPair
from pipeline.decide import decide


def _make_rule(
    rule_id: str,
    catalog: str,
    query: str = "",
    mitre: list[str] | None = None,
    translated: str | None = None,
) -> RuleAST:
    return RuleAST(
        id=rule_id,
        catalog=catalog,
        name=f"Rule {rule_id}",
        description="",
        severity="medium",
        mitre_techniques=mitre or [],
        event_categories=[],
        conditions=[],
        raw_query=query,
        language="eql",
        translated_query=translated,
        source_path="test",
        metadata={},
    )


def _make_result(overlaps, unique_a, unique_b, confidence="logic-only"):
    return CompareResult(
        overlaps=overlaps,
        unique_a=unique_a,
        unique_b=unique_b,
        confidence=confidence,
        catalog_a="sigma",
        catalog_b="elastic",
    )


# ---------------------------------------------------------------------------
# decide() tests
# ---------------------------------------------------------------------------

def test_decide_unique_a_rules_get_add():
    a1 = _make_rule("a1", "sigma")
    result = _make_result(overlaps=[], unique_a=[a1], unique_b=[])
    decisions = decide(result)
    assert decisions["a1"] == "ADD"


def test_decide_overlapping_a_rules_get_skip():
    a1 = _make_rule("a1", "sigma")
    b1 = _make_rule("b1", "elastic")
    pair = OverlapPair(rule_a=a1, rule_b=b1, jaccard_score=0.8)
    result = _make_result(overlaps=[pair], unique_a=[], unique_b=[])
    decisions = decide(result)
    assert decisions["a1"] == "SKIP"


def test_decide_covers_all_rules_in_a():
    a1 = _make_rule("a1", "sigma")
    a2 = _make_rule("a2", "sigma")
    a3 = _make_rule("a3", "sigma")
    b1 = _make_rule("b1", "elastic")
    pair = OverlapPair(rule_a=a1, rule_b=b1, jaccard_score=0.8)
    result = _make_result(overlaps=[pair], unique_a=[a2, a3], unique_b=[])
    decisions = decide(result)
    assert set(decisions.keys()) == {"a1", "a2", "a3"}
    assert decisions["a1"] == "SKIP"
    assert decisions["a2"] == "ADD"
    assert decisions["a3"] == "ADD"


def test_decide_empty_returns_empty():
    result = _make_result(overlaps=[], unique_a=[], unique_b=[])
    assert decide(result) == {}


def test_decide_does_not_include_b_rules():
    b1 = _make_rule("b1", "elastic")
    result = _make_result(overlaps=[], unique_a=[], unique_b=[b1])
    decisions = decide(result)
    assert "b1" not in decisions


def test_decide_rule_in_multiple_overlaps_gets_skip_once():
    a1 = _make_rule("a1", "sigma")
    b1 = _make_rule("b1", "elastic")
    b2 = _make_rule("b2", "elastic")
    pair1 = OverlapPair(rule_a=a1, rule_b=b1, jaccard_score=0.9)
    pair2 = OverlapPair(rule_a=a1, rule_b=b2, jaccard_score=0.7)
    result = _make_result(overlaps=[pair1, pair2], unique_a=[], unique_b=[])
    decisions = decide(result)
    assert decisions["a1"] == "SKIP"
    assert len([k for k, v in decisions.items() if k == "a1"]) == 1


def test_decide_add_count_matches_unique_a():
    rules_a = [_make_rule(f"a{i}", "sigma") for i in range(5)]
    result = _make_result(overlaps=[], unique_a=rules_a, unique_b=[])
    decisions = decide(result)
    add_count = sum(1 for v in decisions.values() if v == "ADD")
    assert add_count == 5


def test_decide_skip_count_matches_distinct_overlapping_a_rules():
    a1 = _make_rule("a1", "sigma")
    a2 = _make_rule("a2", "sigma")
    b1 = _make_rule("b1", "elastic")
    b2 = _make_rule("b2", "elastic")
    pair1 = OverlapPair(rule_a=a1, rule_b=b1, jaccard_score=0.9)
    pair2 = OverlapPair(rule_a=a2, rule_b=b2, jaccard_score=0.8)
    result = _make_result(overlaps=[pair1, pair2], unique_a=[], unique_b=[])
    decisions = decide(result)
    skip_count = sum(1 for v in decisions.values() if v == "SKIP")
    assert skip_count == 2
