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


# ---------------------------------------------------------------------------
# compare_rules() — logic-only mode
# ---------------------------------------------------------------------------

from pipeline.compare import compare_rules


def test_compare_empty_lists_return_empty_result():
    result = compare_rules([], [], threshold=0.15)
    assert result.overlaps == []
    assert result.unique_a == []
    assert result.unique_b == []
    assert result.confidence == "logic-only"


def test_compare_identical_queries_produce_overlap():
    query = 'process where process.name == "cmd.exe"'
    a = _make_rule("a1", "sigma", translated=query)
    b = _make_rule("b1", "elastic", translated=query)
    result = compare_rules([a], [b], threshold=0.15)
    assert len(result.overlaps) == 1
    assert result.overlaps[0].rule_a.id == "a1"
    assert result.overlaps[0].rule_b.id == "b1"
    assert result.overlaps[0].jaccard_score == pytest.approx(1.0)


def test_compare_unrelated_queries_no_overlap():
    a = _make_rule("a1", "sigma", translated='process where process.name == "cmd.exe"')
    b = _make_rule("b1", "elastic", translated='network where destination.port == 443')
    result = compare_rules([a], [b], threshold=0.15)
    assert result.overlaps == []
    assert len(result.unique_a) == 1
    assert len(result.unique_b) == 1


def test_compare_threshold_controls_overlap():
    a = _make_rule("a1", "sigma", translated='process where process.name == "cmd.exe" and process.args == "/c"')
    b = _make_rule("b1", "elastic", translated='process where process.name == "cmd.exe" and user.name == "admin"')
    result_strict = compare_rules([a], [b], threshold=0.99)
    result_loose = compare_rules([a], [b], threshold=0.01)
    assert result_strict.overlaps == [] or result_loose.overlaps != []


def test_compare_unique_a_and_b_are_disjoint_from_overlaps():
    query = 'process where process.name == "cmd.exe"'
    a1 = _make_rule("a1", "sigma", translated=query)
    a2 = _make_rule("a2", "sigma", translated='file where file.name == "malware.exe"')
    b1 = _make_rule("b1", "elastic", translated=query)
    b2 = _make_rule("b2", "elastic", translated='network where destination.port == 4444')
    result = compare_rules([a1, a2], [b1, b2], threshold=0.15)
    overlap_a_ids = {p.rule_a.id for p in result.overlaps}
    overlap_b_ids = {p.rule_b.id for p in result.overlaps}
    unique_a_ids = {r.id for r in result.unique_a}
    unique_b_ids = {r.id for r in result.unique_b}
    assert overlap_a_ids.isdisjoint(unique_a_ids)
    assert overlap_b_ids.isdisjoint(unique_b_ids)


def test_compare_uses_translated_query_if_available():
    a = _make_rule("a1", "sigma", query="sigma: junk", translated='process where process.name == "cmd.exe"')
    b = _make_rule("b1", "elastic", query="sigma: junk", translated='process where process.name == "cmd.exe"')
    result = compare_rules([a], [b], threshold=0.15)
    assert len(result.overlaps) == 1


def test_compare_falls_back_to_raw_query_when_no_translated():
    a = _make_rule("a1", "sigma", query='process where process.name == "cmd.exe"')
    b = _make_rule("b1", "elastic", query='process where process.name == "cmd.exe"')
    result = compare_rules([a], [b], threshold=0.15)
    assert len(result.overlaps) == 1


def test_compare_many_to_many():
    queries = [
        'process where process.name == "cmd.exe"',
        'network where destination.port == 4444',
        'file where file.name == "malware.dll"',
    ]
    rules_a = [_make_rule(f"a{i}", "sigma", translated=q) for i, q in enumerate(queries)]
    rules_b = [_make_rule(f"b{i}", "elastic", translated=q) for i, q in enumerate(queries)]
    result = compare_rules(rules_a, rules_b, threshold=0.15)
    assert len(result.overlaps) == 3
    assert result.unique_a == []
    assert result.unique_b == []


def test_compare_catalog_names_in_result():
    a = _make_rule("a1", "sigma")
    b = _make_rule("b1", "elastic")
    result = compare_rules([a], [b], threshold=0.15)
    assert result.catalog_a == "sigma"
    assert result.catalog_b == "elastic"


# ---------------------------------------------------------------------------
# compare_rules() — alert overlay mode
# ---------------------------------------------------------------------------

def test_compare_alert_confirmed_sets_confidence_full():
    a = _make_rule("a1", "sigma", translated='process where process.name == "cmd.exe"')
    b = _make_rule("b1", "elastic", translated='network where destination.port == 443')
    alerts = [
        {"rule_id": "a1", "catalog": "sigma", "scenario_id": "t1059"},
        {"rule_id": "b1", "catalog": "elastic", "scenario_id": "t1059"},
    ]
    result = compare_rules([a], [b], alerts=alerts, threshold=0.15)
    assert result.confidence == "full"


def test_compare_alert_co_firing_produces_overlap_even_below_threshold():
    a = _make_rule("a1", "sigma", translated='process where process.name == "cmd.exe"')
    b = _make_rule("b1", "elastic", translated='network where destination.port == 443')
    alerts = [
        {"rule_id": "a1", "catalog": "sigma", "scenario_id": "t1059"},
        {"rule_id": "b1", "catalog": "elastic", "scenario_id": "t1059"},
    ]
    result = compare_rules([a], [b], alerts=alerts, threshold=0.15)
    assert len(result.overlaps) == 1
    assert result.overlaps[0].alert_confirmed is True
    assert result.overlaps[0].jaccard_score == pytest.approx(0.0)


def test_compare_different_scenarios_no_alert_overlap():
    a = _make_rule("a1", "sigma", translated='process where process.name == "cmd.exe"')
    b = _make_rule("b1", "elastic", translated='network where destination.port == 443')
    alerts = [
        {"rule_id": "a1", "catalog": "sigma", "scenario_id": "t1059"},
        {"rule_id": "b1", "catalog": "elastic", "scenario_id": "t1021"},
    ]
    result = compare_rules([a], [b], alerts=alerts, threshold=0.15)
    assert result.overlaps == []
    assert len(result.unique_a) == 1
    assert len(result.unique_b) == 1


def test_compare_logic_overlap_also_marked_not_alert_confirmed():
    query = 'process where process.name == "cmd.exe"'
    a = _make_rule("a1", "sigma", translated=query)
    b = _make_rule("b1", "elastic", translated=query)
    alerts = [
        {"rule_id": "a1", "catalog": "sigma", "scenario_id": "t1059"},
        {"rule_id": "b1", "catalog": "elastic", "scenario_id": "t1021"},
    ]
    result = compare_rules([a], [b], alerts=alerts, threshold=0.15)
    assert len(result.overlaps) == 1
    assert result.overlaps[0].alert_confirmed is False
    assert result.overlaps[0].jaccard_score == pytest.approx(1.0)


def test_compare_both_signals_sets_alert_confirmed_true():
    query = 'process where process.name == "cmd.exe"'
    a = _make_rule("a1", "sigma", translated=query)
    b = _make_rule("b1", "elastic", translated=query)
    alerts = [
        {"rule_id": "a1", "catalog": "sigma", "scenario_id": "t1059"},
        {"rule_id": "b1", "catalog": "elastic", "scenario_id": "t1059"},
    ]
    result = compare_rules([a], [b], alerts=alerts, threshold=0.15)
    assert len(result.overlaps) == 1
    assert result.overlaps[0].alert_confirmed is True
    assert result.overlaps[0].jaccard_score == pytest.approx(1.0)


def test_compare_no_alerts_gives_logic_only_confidence():
    a = _make_rule("a1", "sigma", translated='process where process.name == "cmd.exe"')
    b = _make_rule("b1", "elastic", translated='process where process.name == "cmd.exe"')
    result = compare_rules([a], [b])  # no alerts kwarg
    assert result.confidence == "logic-only"


def test_compare_empty_alerts_list_gives_full_confidence():
    a = _make_rule("a1", "sigma", translated='process where process.name == "cmd.exe"')
    b = _make_rule("b1", "elastic", translated='process where process.name == "cmd.exe"')
    result = compare_rules([a], [b], alerts=[])  # explicit empty list = "full" mode
    assert result.confidence == "full"
