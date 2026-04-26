"""
Orchestrates attack chain runners, collects alerts, and persists results.

Usage:
    from attack.sliver import SliverRunner
    from pipeline.attack_chain import run_attack_chain
    from storage.result_store import ResultStore

    store = ResultStore(Path("output"))
    runner = SliverRunner(config={"host": "sliver.lab.local"})
    result = run_attack_chain([runner], store)
    # result.alerts is compatible with compare_rules(alerts=result.alerts)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from attack.base import AttackRunner, AttackScenario, ScenarioResult
from storage.result_store import ResultStore


@dataclass
class AttackChainResult:
    """Aggregated output from one attack chain run."""
    alerts: list[dict]       # compatible with compare_rules(alerts=...)
    run_id: str
    errors: list[str]        # error messages from failed scenarios
    scenario_count: int      # total scenarios attempted


def run_attack_chain(
    runners: list[AttackRunner],
    store: ResultStore,
    run_id: str | None = None,
) -> AttackChainResult:
    """
    Execute all scenarios from all runners, merge alerts, and save to store.

    If a runner raises RuntimeError or NotImplementedError (not configured),
    the error is recorded and execution continues with the next scenario.

    Args:
        runners:  List of AttackRunner instances (Sliver, Atomic, etc.)
        store:    ResultStore for persisting the collected alerts
        run_id:   Optional stable identifier for this run (auto-generated if None)

    Returns:
        AttackChainResult with aggregated alerts, run_id, errors, and scenario count
    """
    if run_id is None:
        run_id = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    all_alerts: list[dict] = []
    errors: list[str] = []
    scenario_count = 0

    for runner in runners:
        for scenario in runner.list_scenarios():
            scenario_count += 1
            try:
                result: ScenarioResult = runner.run_scenario(scenario)
                all_alerts.extend(result.to_alert_dicts())
                if result.error is not None:
                    errors.append(f"{scenario.id}: {result.error}")
            except (RuntimeError, NotImplementedError) as exc:
                errors.append(f"{scenario.id}: {exc}")

    store.save_alerts(run_id, all_alerts)

    return AttackChainResult(
        alerts=all_alerts,
        run_id=run_id,
        errors=errors,
        scenario_count=scenario_count,
    )
