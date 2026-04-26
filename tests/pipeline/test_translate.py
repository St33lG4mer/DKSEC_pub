"""Tests for translate_catalog()."""
import uuid
from unittest.mock import MagicMock, call

import pytest

from adapters.base import BaseAdapter
from core.ast_model import RuleAST
from pipeline.translate import TranslateResult, translate_catalog
from storage.rule_store import RuleStore


def _make_raw(rule_id: str | None = None) -> dict:
    return {"id": rule_id or str(uuid.uuid4()), "title": "Test Rule", "text": "..."}


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
        language="sigma",
        translated_query=None,
        source_path="test/rule.yml",
    )


def _mock_adapter(raws: list[dict], name: str = "sigma") -> BaseAdapter:
    adapter = MagicMock(spec=BaseAdapter)
    adapter.name = name
    return adapter


def test_translate_result_fields():
    r = TranslateResult(catalog="sigma", translated_count=5, failed_count=1, errors=["err"])
    assert r.catalog == "sigma"
    assert r.translated_count == 5
    assert r.failed_count == 1
    assert r.errors == ["err"]


def test_translate_catalog_calls_parse_and_translate(tmp_path):
    store = RuleStore(tmp_path)
    raws = [_make_raw("r1"), _make_raw("r2")]
    store.save_raw("sigma", raws)

    adapter = _mock_adapter(raws)
    ast1 = _make_ast("r1")
    ast2 = _make_ast("r2")
    adapter.parse.side_effect = [ast1, ast2]
    adapter.translate.side_effect = lambda a: a  # identity

    result = translate_catalog(adapter, store)

    assert adapter.parse.call_count == 2
    assert adapter.translate.call_count == 2
    assert result.translated_count == 2
    assert result.failed_count == 0


def test_translate_catalog_saves_asts_to_store(tmp_path):
    store = RuleStore(tmp_path)
    raws = [_make_raw("r1")]
    store.save_raw("sigma", raws)

    adapter = _mock_adapter(raws)
    ast = _make_ast("r1")
    ast.translated_query = "process where process.name == 'cmd.exe'"
    adapter.parse.return_value = ast
    adapter.translate.side_effect = lambda a: a

    translate_catalog(adapter, store)

    loaded = store.load_all("sigma")
    assert len(loaded) == 1
    assert loaded[0].id == "r1"
    assert loaded[0].translated_query == "process where process.name == 'cmd.exe'"


def test_translate_catalog_skips_failed_parse(tmp_path):
    store = RuleStore(tmp_path)
    raws = [_make_raw("r1"), _make_raw("r2")]
    store.save_raw("sigma", raws)

    adapter = _mock_adapter(raws)
    adapter.parse.side_effect = [ValueError("bad rule"), _make_ast("r2")]
    adapter.translate.side_effect = lambda a: a

    result = translate_catalog(adapter, store)

    assert result.translated_count == 1
    assert result.failed_count == 1
    assert len(result.errors) == 1
    assert "bad rule" in result.errors[0]


def test_translate_catalog_no_raw_returns_zero(tmp_path):
    store = RuleStore(tmp_path)
    # No save_raw called — load_raw returns []
    adapter = _mock_adapter([])

    result = translate_catalog(adapter, store)

    assert result.translated_count == 0
    assert result.failed_count == 0
    assert result.errors == []
