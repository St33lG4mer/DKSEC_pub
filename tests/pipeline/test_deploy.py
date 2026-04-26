# tests/pipeline/test_deploy.py
"""Tests for deploy_rules()."""
import uuid
from unittest.mock import MagicMock

import pytest

from adapters.base import BaseAdapter
from core.ast_model import RuleAST
from pipeline.deploy import DeployResult, deploy_rules


def _make_ast(rule_id: str | None = None, catalog: str = "sigma") -> RuleAST:
    return RuleAST(
        id=rule_id or str(uuid.uuid4()),
        catalog=catalog,
        name="Test Rule",
        description="",
        severity="medium",
        mitre_techniques=["attack.t1059.001"],
        event_categories=["process"],
        conditions=[],
        raw_query="any where process.name == 'cmd.exe'",
        language="eql",
        translated_query="process where process.name == 'cmd.exe'",
        source_path="test/rule.yml",
    )


def _mock_adapter(name: str = "sigma") -> BaseAdapter:
    adapter = MagicMock(spec=BaseAdapter)
    adapter.name = name
    adapter.deploy.return_value = True
    return adapter


def test_deploy_result_fields():
    r = DeployResult(catalog="sigma", mode="test", deployed_count=3, failed_count=1, errors=["err"])
    assert r.catalog == "sigma"
    assert r.mode == "test"
    assert r.deployed_count == 3
    assert r.failed_count == 1


def test_deploy_rules_calls_adapter_deploy_for_each():
    adapter = _mock_adapter()
    client = MagicMock()
    rules = [_make_ast("r1"), _make_ast("r2"), _make_ast("r3")]

    result = deploy_rules(adapter, rules, client, mode="test")

    assert adapter.deploy.call_count == 3
    assert result.deployed_count == 3
    assert result.failed_count == 0


def test_deploy_rules_records_failure_and_continues():
    adapter = _mock_adapter()
    client = MagicMock()
    rules = [_make_ast("r1"), _make_ast("r2")]
    adapter.deploy.side_effect = [RuntimeError("SIEM rejected rule"), True]

    result = deploy_rules(adapter, rules, client, mode="test")

    assert result.deployed_count == 1
    assert result.failed_count == 1
    assert len(result.errors) == 1
    assert "SIEM rejected rule" in result.errors[0]


def test_deploy_rules_empty_returns_zero_counts():
    adapter = _mock_adapter()
    client = MagicMock()

    result = deploy_rules(adapter, [], client, mode="test")

    assert result.deployed_count == 0
    assert result.failed_count == 0
    assert result.errors == []


def test_deploy_rules_mode_stored_in_result():
    adapter = _mock_adapter()
    client = MagicMock()
    rules = [_make_ast()]

    test_result = deploy_rules(adapter, rules, client, mode="test")
    perm_result = deploy_rules(adapter, rules, client, mode="permanent")

    assert test_result.mode == "test"
    assert perm_result.mode == "permanent"
