"""
AtomicRunner — executes Atomic Red Team tests against a live SIEM.

Scenarios are registered programmatically via register_scenario().
Requires invoke-atomicredteam or Atomic API. If not configured,
run_scenario() raises RuntimeError cleanly.
"""
from __future__ import annotations

from attack.base import AttackRunner, AttackScenario, ScenarioResult


class AtomicRunner(AttackRunner):
    """
    Attack runner backed by Atomic Red Team.

    Args:
        config: Connection config dict. Required key: "host" (target host for invoke).
    """

    def __init__(self, config: dict | None = None) -> None:
        self._config = config or {}
        self._scenarios: list[AttackScenario] = []

    def register_scenario(self, scenario: AttackScenario) -> None:
        """Add a scenario to this runner's execution list."""
        self._scenarios.append(scenario)

    def list_scenarios(self) -> list[AttackScenario]:
        """Return a copy of the registered scenario list."""
        return list(self._scenarios)

    def run_scenario(self, scenario: AttackScenario) -> ScenarioResult:
        """
        Execute scenario via Atomic Red Team.

        Raises:
            RuntimeError: if config["host"] is not set.
            NotImplementedError: always — live Atomic integration is a future step.
        """
        if not self._config.get("host"):
            raise RuntimeError(
                "AtomicRunner: no host configured. Set config['host'] to the target host."
            )
        raise NotImplementedError(
            "AtomicRunner.run_scenario() requires invoke-atomicredteam on the target host."
        )
