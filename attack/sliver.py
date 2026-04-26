"""
SliverRunner — executes Sliver C2 scenarios against a live SIEM.

Requires a configured Sliver C2 server. If not configured, run_scenario()
raises RuntimeError cleanly. Tests inject scenarios via the constructor.
"""
from __future__ import annotations

from attack.base import AttackRunner, AttackScenario, ScenarioResult


class SliverRunner(AttackRunner):
    """
    Attack runner backed by Sliver C2.

    Args:
        config:    Connection config dict. Required key: "host" (Sliver server address).
        scenarios: Optional scenarios dict (same schema as sliver_test_harness/scenarios.py).
                   If None, loads from sliver_test_harness.scenarios.SCENARIOS at runtime.
    """

    def __init__(
        self,
        config: dict | None = None,
        scenarios: dict | None = None,
    ) -> None:
        self._config = config or {}
        self._raw_scenarios = scenarios  # None = load lazily from sliver_test_harness

    def list_scenarios(self) -> list[AttackScenario]:
        """Return all available Sliver scenarios as AttackScenario objects."""
        raw = self._raw_scenarios
        if raw is None:
            from sliver_test_harness.scenarios import SCENARIOS
            raw = SCENARIOS

        result: list[AttackScenario] = []
        for sid, sdata in raw.items():
            techniques = list({
                step["atck"]
                for step in sdata["steps"]
                if "atck" in step
            })
            result.append(
                AttackScenario(
                    id=sid,
                    description=sdata.get("description", sid),
                    mitre_techniques=techniques,
                    steps=sdata["steps"],
                )
            )
        return result

    def run_scenario(self, scenario: AttackScenario) -> ScenarioResult:
        """
        Execute scenario via Sliver C2.

        Raises:
            RuntimeError: if config["host"] is not set (Sliver not configured).
            NotImplementedError: always — live Sliver integration is a future step.
        """
        if not self._config.get("host"):
            raise RuntimeError(
                "SliverRunner: no host configured. Set config['host'] to the Sliver C2 address."
            )
        raise NotImplementedError(
            "SliverRunner.run_scenario() requires a live Sliver C2 connection."
        )
