"""Tests for CoverageMapRunner."""
from __future__ import annotations

import csv
import uuid
from pathlib import Path

import pytest

from attack.coverage_map_runner import CoverageMapRunner, _rule_uuid

# Path to the real CSV used in tests
_CSV = Path(__file__).parent.parent.parent / "sliver_test_harness" / "coverage_map.csv"


@pytest.fixture(scope="module")
def runner() -> CoverageMapRunner:
    return CoverageMapRunner(_CSV)


# ---------------------------------------------------------------------------
# 1. list_scenarios excludes "uncovered"
# ---------------------------------------------------------------------------

def test_list_scenarios_excludes_uncovered(runner: CoverageMapRunner) -> None:
    ids = {s.id for s in runner.list_scenarios()}
    assert "uncovered" not in ids


# ---------------------------------------------------------------------------
# 2. run_scenario returns correct UUIDs for a known scenario
# ---------------------------------------------------------------------------

def test_run_scenario_returns_correct_slugs(runner: CoverageMapRunner) -> None:
    # Load expected UUIDs for S4_defense_evasion directly from CSV
    expected = [
        _rule_uuid(row["source"], row["slug"])
        for row in csv.DictReader(_CSV.open(encoding="utf-8"))
        if row["scenario_id"] == "S4_defense_evasion"
    ]
    assert expected, "Sanity check: CSV must have S4_defense_evasion rows"

    scenario = next(s for s in runner.list_scenarios() if s.id == "S4_defense_evasion")
    result = runner.run_scenario(scenario)

    assert set(result.fired_rule_ids) == set(expected)
    assert result.raw_alert_count == len(expected)
    assert result.error is None


# ---------------------------------------------------------------------------
# 3. run_all covers all scenarios
# ---------------------------------------------------------------------------

def test_run_all_covers_all_scenarios(runner: CoverageMapRunner) -> None:
    all_results = runner.run_all()
    all_scenarios = runner.list_scenarios()
    assert len(all_results) == len(all_scenarios)
    result_ids = {r.scenario_id for r in all_results}
    scenario_ids = {s.id for s in all_scenarios}
    assert result_ids == scenario_ids


# ---------------------------------------------------------------------------
# 4. fired_rule_ids contains UUIDs from both sigma and elastic catalogs
# ---------------------------------------------------------------------------

def test_fired_rule_ids_both_catalogs(runner: CoverageMapRunner) -> None:
    # S4_defense_evasion has both sigma and elastic rules (verified from CSV)
    rows = list(csv.DictReader(_CSV.open(encoding="utf-8")))
    sigma_uuids = {
        _rule_uuid("sigma", r["slug"])
        for r in rows if r["scenario_id"] == "S4_defense_evasion" and r["source"] == "sigma"
    }
    elastic_uuids = {
        _rule_uuid("elastic", r["slug"])
        for r in rows if r["scenario_id"] == "S4_defense_evasion" and r["source"] == "elastic"
    }

    assert sigma_uuids and elastic_uuids, "Sanity: S4 must have both sigma and elastic rules"

    scenario = next(s for s in runner.list_scenarios() if s.id == "S4_defense_evasion")
    result = runner.run_scenario(scenario)
    fired = set(result.fired_rule_ids)

    assert fired & sigma_uuids, "Should include at least one sigma UUID"
    assert fired & elastic_uuids, "Should include at least one elastic UUID"
