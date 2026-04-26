"""Abstract base class and data types for attack chain runners."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class AttackScenario:
    """A MITRE ATT&CK scenario definition with one or more execution steps."""
    id: str
    description: str
    mitre_techniques: list[str]  # e.g. ["T1059.001", "T1082"]
    steps: list[dict]            # raw step definitions (runner-specific)


@dataclass
class ScenarioResult:
    """Result from executing one AttackScenario against a live SIEM."""
    scenario_id: str
    mitre_techniques: list[str]   # techniques actually exercised
    fired_rule_ids: list[str]     # SIEM rule IDs/names that produced alerts
    raw_alert_count: int
    error: str | None = None      # set if runner failed, None on success

    def to_alert_dicts(self) -> list[dict]:
        """
        Convert to the alert dict format consumed by compare_rules(alerts=...).

        Each dict has:
          rule_id     — the SIEM rule that fired
          scenario_id — the scenario that triggered it
        """
        return [
            {"rule_id": rid, "scenario_id": self.scenario_id}
            for rid in self.fired_rule_ids
        ]


class AttackRunner(ABC):
    """
    Abstract base class for attack chain runners.

    Implementations:
        SliverRunner  — executes Sliver C2 scenarios
        AtomicRunner  — executes Atomic Red Team tests
    """

    @abstractmethod
    def run_scenario(self, scenario: AttackScenario) -> ScenarioResult:
        """Execute a single scenario and return which SIEM rules fired."""

    @abstractmethod
    def list_scenarios(self) -> list[AttackScenario]:
        """Return the list of scenarios this runner can execute."""
