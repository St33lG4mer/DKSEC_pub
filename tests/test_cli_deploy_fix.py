# tests/test_cli_deploy_fix.py
from __future__ import annotations

import json
from pathlib import Path
import pytest
from click.testing import CliRunner
from cli import cli

@pytest.fixture
def tmp_project(tmp_path):
    """Set up a minimal catalog + decisions for deploy tests."""
    # Three sigma rules
    cat_dir = tmp_path / "catalogs" / "sigma" / "ast"
    cat_dir.mkdir(parents=True)
    for rid, name in [("rule-001", "Alpha"), ("rule-002", "Beta"), ("rule-003", "Gamma")]:
        (cat_dir / f"{rid}.json").write_text(json.dumps({
            "id": rid, "catalog": "sigma", "name": name,
            "description": "", "severity": "high",
            "mitre_techniques": [], "event_categories": [],
            "conditions": [], "raw_query": "", "language": "sigma",
            "translated_query": None, "source_path": "", "metadata": {}
        }), encoding="utf-8")

    # Decisions: rule-001 ADD, rule-002 SKIP, rule-003 ADD
    rep_dir = tmp_path / "output" / "reports"
    rep_dir.mkdir(parents=True)
    (rep_dir / "sigma_vs_elastic_decisions.json").write_text(
        json.dumps({"rule-001": "ADD", "rule-002": "SKIP", "rule-003": "ADD"}),
        encoding="utf-8"
    )
    return tmp_path


def test_deploy_dry_run_only_add_rules(tmp_project, monkeypatch):
    """Dry-run deploy must report only ADD-decision rules, not all catalog rules."""
    monkeypatch.setenv("DKSEC_CATALOGS", str(tmp_project / "catalogs"))
    monkeypatch.setenv("DKSEC_OUTPUT", str(tmp_project / "output"))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "deploy", "--mode", "permanent", "--catalog", "sigma",
        "--target", "elastic", "--compare-catalog", "elastic", "--dry-run"
    ])
    assert result.exit_code == 0, result.output
    # Should say 2 rules (rule-001 and rule-003 are ADD), NOT 3
    assert "2 rules" in result.output
    assert "3 rules" not in result.output


def test_deploy_dry_run_no_decisions_falls_back_to_all(tmp_project, monkeypatch):
    """If no decisions file exists, deploy all rules and warn."""
    monkeypatch.setenv("DKSEC_CATALOGS", str(tmp_project / "catalogs"))
    monkeypatch.setenv("DKSEC_OUTPUT", str(tmp_project / "output"))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "deploy", "--mode", "permanent", "--catalog", "sigma",
        "--target", "splunk", "--compare-catalog", "splunk", "--dry-run"
    ])
    assert result.exit_code == 0
    assert "3 rules" in result.output  # all 3 rules (no filter)
    assert "Warning" in result.output