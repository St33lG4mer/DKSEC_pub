"""
CoverageMapRunner — zero-infrastructure attack chain runner.

Reads sliver_test_harness/coverage_map.csv to simulate scenario execution:
rules mapped to a scenario_id are treated as "fired" for that scenario.
No live SIEM or C2 infrastructure required.
"""
from __future__ import annotations

import csv
import uuid
from collections import defaultdict
from pathlib import Path

from attack.base import AttackRunner, AttackScenario, ScenarioResult

# Default CSV path relative to this file: attack/ → project root → sliver_test_harness/
_DEFAULT_CSV = Path(__file__).parent.parent / "sliver_test_harness" / "coverage_map.csv"


def _rule_uuid(source: str, slug: str) -> str:
    """Compute the deterministic UUID for a rule, matching migrate_rule_ast.py."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{source}:{slug}"))


class CoverageMapRunner(AttackRunner):
    """
    Attack runner backed by the static coverage map CSV.

    Parses coverage_map.csv once at construction time, then serves
    list_scenarios() and run_scenario() entirely from in-memory dicts.
    Rules with scenario_id == "uncovered" are excluded.

    fired_rule_ids in ScenarioResult contains deterministic UUIDs that match
    the rule IDs used in catalogs/{sigma,elastic}/ast/.

    Args:
        csv_path: Path to coverage_map.csv. Defaults to
                  sliver_test_harness/coverage_map.csv relative to this file.
    """

    def __init__(self, csv_path: Path | str | None = None) -> None:
        path = Path(csv_path) if csv_path is not None else _DEFAULT_CSV
        # Store (source, slug) pairs per scenario to compute UUIDs on demand
        self._scenario_rules: dict[str, list[tuple[str, str]]] = defaultdict(list)
        self._scenario_order: list[str] = []

        with path.open(encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                sid = row["scenario_id"]
                if sid == "uncovered":
                    continue
                slug = row["slug"]
                source = row["source"]
                if sid not in self._scenario_rules:
                    self._scenario_order.append(sid)
                self._scenario_rules[sid].append((source, slug))

    # ------------------------------------------------------------------
    # AttackRunner interface
    # ------------------------------------------------------------------

    def list_scenarios(self) -> list[AttackScenario]:
        """Return one AttackScenario per unique scenario_id (excluding 'uncovered')."""
        from sliver_test_harness.scenarios import SCENARIOS

        scenarios: list[AttackScenario] = []
        for sid in self._scenario_order:
            meta = SCENARIOS.get(sid)
            if meta:
                steps = meta["steps"]
                description = meta["description"]
                techniques = sorted({
                    step["atck"]
                    for step in steps
                    if step.get("atck")
                })
            else:
                steps = []
                description = sid
                techniques = []

            scenarios.append(
                AttackScenario(
                    id=sid,
                    description=description,
                    mitre_techniques=techniques,
                    steps=steps,
                )
            )
        return scenarios

    def run_scenario(self, scenario: AttackScenario) -> ScenarioResult:
        """
        Return a ScenarioResult whose fired_rule_ids are deterministic UUIDs
        matching the rule IDs in catalogs/{sigma,elastic}/ast/.
        """
        rules = self._scenario_rules.get(scenario.id, [])
        fired_ids = [_rule_uuid(source, slug) for source, slug in rules]
        return ScenarioResult(
            scenario_id=scenario.id,
            mitre_techniques=scenario.mitre_techniques,
            fired_rule_ids=fired_ids,
            raw_alert_count=len(fired_ids),
            error=None,
        )

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def run_all(self) -> list[ScenarioResult]:
        """Run all scenarios and return results."""
        return [self.run_scenario(s) for s in self.list_scenarios()]
