"""
Integration tests: attack chain -> compare -> decide full pipeline.
"""
import pytest
from unittest.mock import MagicMock
from pathlib import Path

from attack.base import AttackRunner, AttackScenario, ScenarioResult
from pipeline.attack_chain import run_attack_chain
from pipeline.compare import compare_rules
from pipeline.decide import decide
from storage.result_store import ResultStore
from core.ast_model import RuleAST


def _make_rule(
    rule_id: str,
    catalog: str = "elastic",
    query: str = "",
    mitre: list[str] | None = None,
    translated: str | None = None,
    name: str | None = None,  # explicit name overrides the default
) -> RuleAST:
    """Helper to create RuleAST for testing."""
    return RuleAST(
        id=rule_id,
        catalog=catalog,
        name=name or f"Rule {rule_id}",
        description="",
        severity="medium",
        mitre_techniques=mitre or ["T1059.001"],
        event_categories=[],
        conditions=[],
        raw_query=query,
        language="eql",
        translated_query=translated,
        source_path="test",
        metadata={},
    )


def _scenario(sid: str) -> AttackScenario:
    """Helper to create AttackScenario for testing."""
    return AttackScenario(
        id=sid,
        description=f"Scenario {sid}",
        mitre_techniques=["T1059.001"],
        steps=[],
    )


def _mock_runner(
    scenarios: list[AttackScenario],
    fired_by_scenario: dict[str, list[str]],
) -> AttackRunner:
    """
    Create a mock AttackRunner that returns predefined scenario results.
    
    Args:
        scenarios: List of scenarios the runner can execute
        fired_by_scenario: Dict mapping scenario_id to list of rule IDs that fired
    """
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


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------


def test_full_pipeline_unique_rules_get_add_decision(tmp_path):
    """
    Full pipeline: attack -> compare -> decide.
    
    Scenario: rule-a (Sigma) has unique logic (no match with any Elastic rule).
    Expected: rule-a has no overlap → unique_a → ADD decision.
    """
    store = ResultStore(tmp_path)
    s1 = _scenario("S1")
    
    # Mock runner: S1 fires rule-b only
    runner = _mock_runner([s1], {"S1": ["rule-b"]})
    
    # Run attack chain to generate alerts
    chain_result = run_attack_chain([runner], store, run_id="run1")
    
    # Create rules with different queries:
    # rule-a (Sigma): process detection
    # rule-b (Elastic): network detection (different, no overlap)
    rule_a = _make_rule("rule-a", catalog="sigma",
                        translated='process where process.name == "cmd.exe"',
                        name="sigma_cmdexec_process_alpha")
    rule_b = _make_rule("rule-b", catalog="elastic",
                        translated='network where destination.port == 443',
                        name="elastic_network_portmon_beta")
    
    # Compare with alerts from chain
    compare_result = compare_rules(
        rules_a=[rule_a],
        rules_b=[rule_b],
        alerts=chain_result.alerts,
    )
    
    # Decide: rule-a should be ADD (unique, no overlap with rule-b)
    decisions = decide(compare_result)
    
    assert decisions.get("rule-a") == "ADD"
    assert compare_result.confidence == "full"


def test_full_pipeline_overlapping_rule_gets_skip_decision(tmp_path):
    """
    Full pipeline with co-firing rules.
    
    Scenario: rule-x and rule-y both fire in scenario S1.
    Expected: Both rules appear in alerts same scenario → overlap → SKIP.
    """
    store = ResultStore(tmp_path)
    s1 = _scenario("S1")
    
    # Mock runner: S1 fires both rule-x and rule-y
    runner = _mock_runner([s1], {"S1": ["rule-x", "rule-y"]})
    
    chain_result = run_attack_chain([runner], store, run_id="run2")
    
    rule_x = _make_rule("rule-x", catalog="sigma", translated='process where process.name == "cmd.exe"')
    rule_y = _make_rule("rule-y", catalog="elastic", translated='network where destination.port == 443')
    
    compare_result = compare_rules(
        rules_a=[rule_x],
        rules_b=[rule_y],
        alerts=chain_result.alerts,
    )
    decisions = decide(compare_result)
    
    # Both fired in same scenario → alert_confirmed overlap → SKIP
    assert decisions.get("rule-x") == "SKIP"
    assert compare_result.confidence == "full"


def test_full_pipeline_alerts_persisted_and_reloadable(tmp_path):
    """
    Verify alerts saved by run_attack_chain can be reloaded and used.
    
    Scenario: Run attack chain, reload alerts, use for comparison.
    Expected: Reloaded alerts match original; decisions consistent.
    """
    store = ResultStore(tmp_path)
    s1 = _scenario("S1")
    
    runner = _mock_runner([s1], {"S1": ["rule-1"]})
    
    # Run chain and save alerts
    chain_result = run_attack_chain([runner], store, run_id="persist-run")
    original_alerts = chain_result.alerts
    
    # Reload alerts from store
    reloaded_alerts = store.load_alerts("persist-run")
    
    rule_1 = _make_rule("rule-1", catalog="sigma",
                        translated='process where process.name == "cmd.exe"',
                        name="sigma_cmdexec_process_one")
    rule_2 = _make_rule("rule-2", catalog="elastic",
                        translated='file where file.name == "test.txt"',
                        name="elastic_filewatch_monitor_two")
    
    compare_result = compare_rules(
        rules_a=[rule_1],
        rules_b=[rule_2],
        alerts=reloaded_alerts,
    )
    decisions = decide(compare_result)
    
    # rule-1 fired and is in rules_a, rule-2 didn't fire
    # If they fired in same scenario, would overlap, but rule-2 never fired
    assert compare_result.confidence == "full"
    # rule-1 has no overlap with rule-2 (different queries, rule-2 never fired)
    assert decisions.get("rule-1") == "ADD"
    # Verify reloaded alerts match original
    assert len(reloaded_alerts) == len(original_alerts)
    if original_alerts:
        assert reloaded_alerts[0]["rule_id"] == "rule-1"
        assert reloaded_alerts[0]["scenario_id"] == "S1"
