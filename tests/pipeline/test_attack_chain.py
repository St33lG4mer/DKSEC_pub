"""Tests for run_attack_chain()."""
import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

from attack.base import AttackRunner, AttackScenario, ScenarioResult
from pipeline.attack_chain import AttackChainResult, run_attack_chain
from storage.result_store import ResultStore


def _make_scenario(sid: str = "S1") -> AttackScenario:
    return AttackScenario(
        id=sid,
        description=f"Scenario {sid}",
        mitre_techniques=["T1059.001"],
        steps=[],
    )


def _mock_runner(scenarios: list[AttackScenario], fired_by_scenario: dict[str, list[str]]) -> AttackRunner:
    """Create a mock runner that returns pre-canned ScenarioResults."""
    runner = MagicMock(spec=AttackRunner)
    runner.list_scenarios.return_value = scenarios

    def _run(scenario):
        fired = fired_by_scenario.get(scenario.id, [])
        return ScenarioResult(
            scenario_id=scenario.id,
            mitre_techniques=scenario.mitre_techniques,
            fired_rule_ids=fired,
            raw_alert_count=len(fired),
        )
    runner.run_scenario.side_effect = _run
    return runner


def test_attack_chain_result_stores_fields():
    r = AttackChainResult(alerts=[{"rule_id": "r1", "scenario_id": "S1"}], run_id="run-1", errors=[], scenario_count=1)
    assert r.run_id == "run-1"
    assert len(r.alerts) == 1
    assert r.errors == []
    assert r.scenario_count == 1


def test_run_attack_chain_collects_alerts(tmp_path):
    store = ResultStore(tmp_path)
    s1 = _make_scenario("S1")
    runner = _mock_runner([s1], {"S1": ["rule-a", "rule-b"]})

    result = run_attack_chain([runner], store, run_id="run-1")

    assert len(result.alerts) == 2
    assert result.scenario_count == 1
    assert result.errors == []


def test_run_attack_chain_saves_alerts_to_store(tmp_path):
    store = ResultStore(tmp_path)
    s1 = _make_scenario("S1")
    runner = _mock_runner([s1], {"S1": ["rule-x"]})

    run_attack_chain([runner], store, run_id="myrun")

    loaded = store.load_alerts("myrun")
    assert len(loaded) == 1
    assert loaded[0]["rule_id"] == "rule-x"
    assert loaded[0]["scenario_id"] == "S1"


def test_run_attack_chain_merges_multiple_runners(tmp_path):
    store = ResultStore(tmp_path)
    s1 = _make_scenario("S1")
    s2 = _make_scenario("S2")
    runner_a = _mock_runner([s1], {"S1": ["rule-1"]})
    runner_b = _mock_runner([s2], {"S2": ["rule-2", "rule-3"]})

    result = run_attack_chain([runner_a, runner_b], store, run_id="r1")

    assert len(result.alerts) == 3
    assert result.scenario_count == 2


def test_run_attack_chain_records_runtime_error_and_continues(tmp_path):
    store = ResultStore(tmp_path)
    s1 = _make_scenario("S1")
    s2 = _make_scenario("S2")

    failing_runner = MagicMock(spec=AttackRunner)
    failing_runner.list_scenarios.return_value = [s1]
    failing_runner.run_scenario.side_effect = RuntimeError("not configured")

    good_runner = _mock_runner([s2], {"S2": ["rule-ok"]})

    result = run_attack_chain([failing_runner, good_runner], store, run_id="r1")

    assert len(result.alerts) == 1
    assert result.alerts[0]["rule_id"] == "rule-ok"
    assert len(result.errors) == 1
    assert "not configured" in result.errors[0]


def test_run_attack_chain_empty_runners_returns_empty(tmp_path):
    store = ResultStore(tmp_path)
    result = run_attack_chain([], store, run_id="empty")
    assert result.alerts == []
    assert result.errors == []
    assert result.scenario_count == 0


def test_run_attack_chain_auto_generates_run_id_when_none(tmp_path):
    store = ResultStore(tmp_path)
    runner = _mock_runner([], {})
    result = run_attack_chain([runner], store)
    assert result.run_id != ""
    assert len(result.run_id) > 0
