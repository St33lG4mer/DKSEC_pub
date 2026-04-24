"""
Integration test: compare → decide → ResultStore round-trip.
Uses in-memory temp dirs — no live SIEM or filesystem state.
"""
import json
import pytest
import tempfile
from pathlib import Path

from core.ast_model import RuleAST
from pipeline.compare import compare_rules, CompareResult
from pipeline.decide import decide
from storage.result_store import ResultStore


def _make_rule(
    rule_id: str,
    catalog: str,
    query: str = "",
    translated: str | None = None,
    mitre: list[str] | None = None,
) -> RuleAST:
    return RuleAST(
        id=rule_id,
        catalog=catalog,
        name=f"Rule {rule_id}",
        description="test rule",
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


SHARED_QUERY = 'process where process.name == "cmd.exe" and process.args == "/c whoami"'
UNIQUE_SIGMA = 'process where process.name == "mshta.exe" and process.args like~ "*.hta"'
UNIQUE_ELASTIC = 'network where destination.port == 4444 and process.name == "powershell.exe"'


@pytest.fixture
def store(tmp_path):
    return ResultStore(tmp_path)


def test_full_pipeline_logic_only(store):
    """compare → decide → store round trip, logic-only mode."""
    sigma_rules = [
        _make_rule("s1", "sigma", translated=SHARED_QUERY),
        _make_rule("s2", "sigma", translated=UNIQUE_SIGMA),
    ]
    elastic_rules = [
        _make_rule("e1", "elastic", translated=SHARED_QUERY),
        _make_rule("e2", "elastic", translated=UNIQUE_ELASTIC),
    ]

    result = compare_rules(sigma_rules, elastic_rules, threshold=0.15)
    assert result.confidence == "logic-only"
    assert len(result.overlaps) == 2  # s1-e1 (perfect), s2-e1 (above threshold)
    assert len(result.unique_a) == 0
    assert len(result.unique_b) == 1

    decisions = decide(result)
    assert decisions["s1"] == "SKIP"
    assert decisions["s2"] == "SKIP"

    # Persist and reload
    overlaps_dicts, unique_a_dicts = result.to_storage_dicts()
    store.save_overlaps("sigma", "elastic", overlaps_dicts)
    store.save_unique("sigma", "elastic", unique_a_dicts)
    store.save_decisions("sigma", "elastic", decisions)

    loaded_overlaps = store.load_overlaps("sigma", "elastic")
    loaded_unique = store.load_unique("sigma", "elastic")
    loaded_decisions = store.load_decisions("sigma", "elastic")

    assert len(loaded_overlaps) == 2
    assert loaded_overlaps[0]["rule_a_id"] == "s1"
    assert len(loaded_unique) == 0
    assert loaded_decisions["s1"] == "SKIP"
    assert loaded_decisions["s2"] == "SKIP"


def test_full_pipeline_with_alert_overlay(store):
    """compare → decide → store round trip, alert overlay mode."""
    sigma_rules = [
        _make_rule("s1", "sigma", translated='process where process.name == "cmd.exe"'),
        _make_rule("s2", "sigma", translated=UNIQUE_SIGMA),
    ]
    elastic_rules = [
        _make_rule("e1", "elastic", translated='network where destination.port == 443'),  # different logic
        _make_rule("e2", "elastic", translated=UNIQUE_ELASTIC),
    ]
    # s1 and e1 have no logic overlap but co-fired on same scenario
    alerts = [
        {"rule_id": "s1", "catalog": "sigma", "scenario_id": "t1059"},
        {"rule_id": "e1", "catalog": "elastic", "scenario_id": "t1059"},
    ]

    result = compare_rules(sigma_rules, elastic_rules, alerts=alerts, threshold=0.15)
    assert result.confidence == "full"
    assert len(result.overlaps) == 1
    assert result.overlaps[0].alert_confirmed is True

    decisions = decide(result)
    assert decisions["s1"] == "SKIP"
    assert decisions["s2"] == "ADD"


def test_full_pipeline_all_unique(store):
    """When no rules overlap, all sigma rules → ADD."""
    sigma_rules = [_make_rule(f"s{i}", "sigma", translated=UNIQUE_SIGMA) for i in range(3)]
    elastic_rules = [_make_rule(f"e{i}", "elastic", translated=UNIQUE_ELASTIC) for i in range(3)]

    result = compare_rules(sigma_rules, elastic_rules, threshold=0.15)
    assert result.overlaps == []
    decisions = decide(result)
    assert all(v == "ADD" for v in decisions.values())
    assert len(decisions) == 3


def test_full_pipeline_all_overlap(store):
    """When every sigma rule overlaps, all → SKIP."""
    sigma_rules = [_make_rule(f"s{i}", "sigma", translated=SHARED_QUERY) for i in range(3)]
    elastic_rules = [_make_rule(f"e{i}", "elastic", translated=SHARED_QUERY) for i in range(3)]

    result = compare_rules(sigma_rules, elastic_rules, threshold=0.15)
    decisions = decide(result)
    assert all(v == "SKIP" for v in decisions.values())
    assert len(decisions) == 3
