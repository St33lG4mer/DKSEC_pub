"""Tests for the DKSec CLI (cli.py)."""
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from cli import cli


def _runner():
    return CliRunner()


# ------------------------------------------------------------------
# 1. Help output lists all commands
# ------------------------------------------------------------------
def test_cli_help_shows_commands():
    result = _runner().invoke(cli, ["--help"])
    assert result.exit_code == 0
    for cmd in ("ingest", "translate", "compare", "decide", "attack", "deploy", "run-all"):
        assert cmd in result.output, f"Expected '{cmd}' in help output"


# ------------------------------------------------------------------
# 2. ingest command calls ingest_catalog
# ------------------------------------------------------------------
def test_ingest_command_calls_ingest_catalog(tmp_path):
    sigma_dir = tmp_path / "sigma"
    sigma_dir.mkdir()
    mock_result = MagicMock(catalog="sigma", raw_count=5, failed_count=0, errors=[])
    with patch("cli.ingest_catalog", return_value=mock_result) as mock_ingest, \
         patch("cli._make_adapter", return_value=MagicMock()), \
         patch("cli.RuleStore", return_value=MagicMock()):
        result = _runner().invoke(cli, [
            "ingest", "--catalog", "sigma", "--source", "folder", "--path", str(sigma_dir)
        ])
    assert result.exit_code == 0, result.output
    assert "5" in result.output
    mock_ingest.assert_called_once()


# ------------------------------------------------------------------
# 3. translate command calls translate_catalog
# ------------------------------------------------------------------
def test_translate_command_calls_translate_catalog():
    mock_result = MagicMock(catalog="sigma", translated_count=3, failed_count=0, errors=[])
    with patch("cli.translate_catalog", return_value=mock_result), \
         patch("cli._make_adapter", return_value=MagicMock()), \
         patch("cli.RuleStore", return_value=MagicMock()):
        result = _runner().invoke(cli, ["translate", "--catalog", "sigma"])
    assert result.exit_code == 0, result.output
    assert "3" in result.output


# ------------------------------------------------------------------
# 4. compare command calls compare_rules and saves results
# ------------------------------------------------------------------
def test_compare_command_calls_compare_rules():
    from pipeline.compare import CompareResult
    mock_store = MagicMock()
    mock_store.load_all.return_value = []
    mock_result_store = MagicMock()
    compare_result = CompareResult(
        overlaps=[], unique_a=[], unique_b=[],
        confidence="logic-only", catalog_a="sigma", catalog_b="elastic"
    )
    compare_result_store_value = ([], [])
    with patch("cli.RuleStore", return_value=mock_store), \
         patch("cli.ResultStore", return_value=mock_result_store), \
         patch("cli.compare_rules", return_value=compare_result) as mock_cmp:
        result = _runner().invoke(cli, ["compare", "--a", "sigma", "--b", "elastic"])
    assert result.exit_code == 0, result.output
    assert "logic-only" in result.output
    mock_cmp.assert_called_once()


# ------------------------------------------------------------------
# 5. decide command calls _decide_pipeline
# ------------------------------------------------------------------
def test_decide_command_calls_decide():
    from pipeline.compare import CompareResult
    mock_store = MagicMock()
    mock_store.load_all.return_value = []
    mock_result_store = MagicMock()
    compare_result = CompareResult(
        overlaps=[], unique_a=[], unique_b=[],
        confidence="logic-only", catalog_a="sigma", catalog_b="elastic"
    )
    decisions = {"rule-1": "ADD", "rule-2": "SKIP"}
    with patch("cli.RuleStore", return_value=mock_store), \
         patch("cli.ResultStore", return_value=mock_result_store), \
         patch("cli.compare_rules", return_value=compare_result), \
         patch("cli._decide_pipeline", return_value=decisions) as mock_decide:
        result = _runner().invoke(cli, ["decide", "--a", "sigma", "--b", "elastic"])
    assert result.exit_code == 0, result.output
    mock_decide.assert_called_once()
    assert "ADD" in result.output or "1" in result.output


# ------------------------------------------------------------------
# 6. deploy command: missing required options causes non-zero exit
# ------------------------------------------------------------------
def test_deploy_missing_required_options():
    result = _runner().invoke(cli, ["deploy", "--mode", "test"])
    assert result.exit_code != 0


# ------------------------------------------------------------------
# 7. run-all with --skip-attack completes successfully
# ------------------------------------------------------------------
def test_run_all_skip_attack_flag():
    from pipeline.compare import CompareResult
    mock_store = MagicMock()
    mock_store.load_all.return_value = []
    mock_result_store = MagicMock()
    compare_result = CompareResult(
        overlaps=[], unique_a=[], unique_b=[],
        confidence="logic-only", catalog_a="sigma", catalog_b="elastic"
    )
    with patch("cli.RuleStore", return_value=mock_store), \
         patch("cli.ResultStore", return_value=mock_result_store), \
         patch("cli._make_adapter", return_value=MagicMock()), \
         patch("cli.ingest_catalog", return_value=MagicMock(catalog="sigma", raw_count=0, failed_count=0, errors=[])), \
         patch("cli.translate_catalog", return_value=MagicMock(catalog="sigma", translated_count=0, failed_count=0, errors=[])), \
         patch("cli.compare_rules", return_value=compare_result), \
         patch("cli._decide_pipeline", return_value={}):
        result = _runner().invoke(cli, [
            "run-all", "--a", "sigma", "--b", "elastic", "--skip-attack"
        ])
    assert result.exit_code == 0, result.output


# ------------------------------------------------------------------
# 8. attack command: missing --framework causes non-zero exit
# ------------------------------------------------------------------
def test_attack_missing_framework():
    result = _runner().invoke(cli, ["attack"])
    assert result.exit_code != 0
