"""Tests for AttackScenario, ScenarioResult, and AttackRunner ABC."""
import pytest
from attack.base import AttackRunner, AttackScenario, ScenarioResult


def _make_scenario(sid: str = "S1", techniques: list[str] | None = None) -> AttackScenario:
    return AttackScenario(
        id=sid,
        description=f"Scenario {sid}",
        mitre_techniques=techniques or ["T1059.001"],
        steps=[{"name": "step1", "kind": "shell", "command": "cmd.exe", "args": []}],
    )


def _make_result(sid: str = "S1", fired: list[str] | None = None) -> ScenarioResult:
    fired_list = fired if fired is not None else ["rule-1", "rule-2"]
    return ScenarioResult(
        scenario_id=sid,
        mitre_techniques=["T1059.001"],
        fired_rule_ids=fired_list,
        raw_alert_count=len(fired_list),
    )


def test_scenario_stores_fields():
    s = _make_scenario("S1", ["T1059.001", "T1082"])
    assert s.id == "S1"
    assert s.description == "Scenario S1"
    assert s.mitre_techniques == ["T1059.001", "T1082"]
    assert len(s.steps) == 1


def test_result_stores_fields():
    r = _make_result("S1", ["r1", "r2", "r3"])
    assert r.scenario_id == "S1"
    assert r.fired_rule_ids == ["r1", "r2", "r3"]
    assert r.raw_alert_count == 3
    assert r.error is None


def test_result_error_field_defaults_none():
    r = ScenarioResult(
        scenario_id="S1",
        mitre_techniques=[],
        fired_rule_ids=[],
        raw_alert_count=0,
    )
    assert r.error is None


def test_result_error_field_can_be_set():
    r = ScenarioResult(
        scenario_id="S1",
        mitre_techniques=[],
        fired_rule_ids=[],
        raw_alert_count=0,
        error="Sliver C2 unreachable",
    )
    assert r.error == "Sliver C2 unreachable"


def test_to_alert_dicts_returns_one_dict_per_fired_rule():
    r = _make_result("S1", ["rule-a", "rule-b"])
    alerts = r.to_alert_dicts()
    assert len(alerts) == 2


def test_to_alert_dicts_contains_rule_id_and_scenario_id():
    r = _make_result("T1059", ["rule-x"])
    alerts = r.to_alert_dicts()
    assert alerts[0]["rule_id"] == "rule-x"
    assert alerts[0]["scenario_id"] == "T1059"


def test_to_alert_dicts_empty_fired_returns_empty():
    r = _make_result("S1", [])
    assert r.to_alert_dicts() == []


def test_attack_runner_is_abstract():
    with pytest.raises(TypeError):
        AttackRunner()  # type: ignore
