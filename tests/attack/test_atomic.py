"""Tests for AtomicRunner."""
import pytest
from attack.base import AttackScenario, ScenarioResult
from attack.atomic import AtomicRunner


def _make_scenario(sid: str = "T1059.001") -> AttackScenario:
    return AttackScenario(
        id=sid,
        description=f"Atomic test {sid}",
        mitre_techniques=[sid],
        steps=[{"name": "exec", "kind": "shell", "command": "powershell.exe", "args": ["-c", "whoami"]}],
    )


def test_atomic_runner_starts_with_no_scenarios():
    runner = AtomicRunner()
    assert runner.list_scenarios() == []


def test_atomic_runner_register_scenario_adds_it():
    runner = AtomicRunner()
    s = _make_scenario("T1059.001")
    runner.register_scenario(s)
    assert len(runner.list_scenarios()) == 1
    assert runner.list_scenarios()[0].id == "T1059.001"


def test_atomic_runner_register_multiple_scenarios():
    runner = AtomicRunner()
    runner.register_scenario(_make_scenario("T1059.001"))
    runner.register_scenario(_make_scenario("T1082"))
    assert len(runner.list_scenarios()) == 2


def test_atomic_runner_run_scenario_raises_when_not_configured():
    runner = AtomicRunner()
    runner.register_scenario(_make_scenario())
    with pytest.raises(RuntimeError, match="AtomicRunner"):
        runner.run_scenario(runner.list_scenarios()[0])


def test_atomic_runner_run_scenario_raises_when_missing_host():
    runner = AtomicRunner(config={"user": "admin"})
    runner.register_scenario(_make_scenario())
    with pytest.raises(RuntimeError, match="host"):
        runner.run_scenario(runner.list_scenarios()[0])


def test_atomic_runner_list_scenarios_returns_copy():
    runner = AtomicRunner()
    runner.register_scenario(_make_scenario())
    result = runner.list_scenarios()
    result.clear()
    # Internal list not mutated
    assert len(runner.list_scenarios()) == 1
