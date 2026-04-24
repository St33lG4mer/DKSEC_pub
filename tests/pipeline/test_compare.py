"""Tests for compare_rules() and related data types."""
import pytest
from core.ast_model import RuleAST
from pipeline.compare import OverlapPair, CompareResult


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


# ---------------------------------------------------------------------------
# OverlapPair
# ---------------------------------------------------------------------------

def test_overlap_pair_to_dict_contains_ids():
    a = _make_rule("a1", "sigma")
    b = _make_rule("b1", "elastic")
    pair = OverlapPair(rule_a=a, rule_b=b, jaccard_score=0.5)
    d = pair.to_dict()
    assert d["rule_a_id"] == "a1"
    assert d["rule_b_id"] == "b1"
    assert d["jaccard_score"] == 0.5
    assert d["alert_confirmed"] is False


def test_overlap_pair_to_dict_alert_confirmed():
    a = _make_rule("a1", "sigma")
    b = _make_rule("b1", "elastic")
    pair = OverlapPair(rule_a=a, rule_b=b, jaccard_score=0.3, alert_confirmed=True)
    assert pair.to_dict()["alert_confirmed"] is True


def test_overlap_pair_to_dict_contains_names_and_catalogs():
    a = _make_rule("a1", "sigma")
    b = _make_rule("b1", "elastic")
    pair = OverlapPair(rule_a=a, rule_b=b, jaccard_score=0.4)
    d = pair.to_dict()
    assert d["rule_a_catalog"] == "sigma"
    assert d["rule_b_catalog"] == "elastic"
    assert "rule_a_name" in d
    assert "rule_b_name" in d


# ---------------------------------------------------------------------------
# CompareResult
# ---------------------------------------------------------------------------

def test_compare_result_to_storage_dicts():
    a = _make_rule("a1", "sigma")
    b = _make_rule("b1", "elastic")
    a2 = _make_rule("a2", "sigma")
    pair = OverlapPair(rule_a=a, rule_b=b, jaccard_score=0.6)
    result = CompareResult(
        overlaps=[pair],
        unique_a=[a2],
        unique_b=[b],
        confidence="logic-only",
        catalog_a="sigma",
        catalog_b="elastic",
    )
    overlaps_dicts, unique_a_dicts = result.to_storage_dicts()
    assert len(overlaps_dicts) == 1
    assert overlaps_dicts[0]["rule_a_id"] == "a1"
    assert len(unique_a_dicts) == 1
    assert unique_a_dicts[0]["id"] == "a2"


def test_compare_result_confidence_stored():
    result = CompareResult(
        overlaps=[],
        unique_a=[],
        unique_b=[],
        confidence="full",
        catalog_a="sigma",
        catalog_b="elastic",
    )
    assert result.confidence == "full"
