"""Tests for SliverRunner."""
import pytest
from attack.base import AttackScenario, ScenarioResult
from attack.sliver import SliverRunner

FAKE_SCENARIOS = {
    "S1_recon": {
        "description": "Initial recon",
        "steps": [
            {"name": "whoami", "kind": "native", "atck": "T1033", "command": "execute", "args": ["-o", "whoami"]},
            {"name": "systeminfo", "kind": "native", "atck": "T1082", "command": "execute", "args": ["-o", "systeminfo"]},
        ],
    },
    "S2_creds": {
        "description": "Credential theft",
        "steps": [
            {"name": "mimikatz", "kind": "execute_assembly", "atck": "T1003.001", "command": "Mimikatz.exe", "args": ["sekurlsa::logonpasswords"]},
        ],
    },
}


def test_sliver_runner_list_scenarios_returns_attack_scenarios():
    runner = SliverRunner(scenarios=FAKE_SCENARIOS)
    scenarios = runner.list_scenarios()
    assert len(scenarios) == 2
    assert all(isinstance(s, AttackScenario) for s in scenarios)


def test_sliver_runner_scenario_ids_match_keys():
    runner = SliverRunner(scenarios=FAKE_SCENARIOS)
    ids = {s.id for s in runner.list_scenarios()}
    assert ids == {"S1_recon", "S2_creds"}


def test_sliver_runner_extracts_mitre_techniques_from_steps():
    runner = SliverRunner(scenarios=FAKE_SCENARIOS)
    scenarios = {s.id: s for s in runner.list_scenarios()}
    assert "T1033" in scenarios["S1_recon"].mitre_techniques
    assert "T1082" in scenarios["S1_recon"].mitre_techniques
    assert "T1003.001" in scenarios["S2_creds"].mitre_techniques


def test_sliver_runner_run_scenario_raises_when_not_configured():
    runner = SliverRunner(scenarios=FAKE_SCENARIOS)
    scenario = runner.list_scenarios()[0]
    with pytest.raises(RuntimeError, match="SliverRunner"):
        runner.run_scenario(scenario)


def test_sliver_runner_run_scenario_raises_even_with_partial_config():
    runner = SliverRunner(config={"port": 31337}, scenarios=FAKE_SCENARIOS)
    scenario = runner.list_scenarios()[0]
    with pytest.raises(RuntimeError, match="host"):
        runner.run_scenario(scenario)


def test_sliver_runner_empty_scenarios():
    runner = SliverRunner(scenarios={})
    assert runner.list_scenarios() == []
