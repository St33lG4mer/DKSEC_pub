# tests/pipeline/test_ingest.py
"""Tests for ingest_catalog()."""
import uuid
from unittest.mock import MagicMock

import pytest

from adapters.base import BaseAdapter
from core.ast_model import RuleAST
from pipeline.ingest import IngestResult, ingest_catalog
from storage.rule_store import RuleStore


def _make_raw(rule_id: str | None = None) -> dict:
    return {"id": rule_id or str(uuid.uuid4()), "title": "Test Rule", "text": "..."}


def _mock_adapter(raws: list[dict], name: str = "sigma") -> BaseAdapter:
    adapter = MagicMock(spec=BaseAdapter)
    adapter.name = name
    adapter.load.return_value = raws
    return adapter


def test_ingest_result_fields():
    r = IngestResult(catalog="sigma", raw_count=3, failed_count=0, errors=[])
    assert r.catalog == "sigma"
    assert r.raw_count == 3
    assert r.failed_count == 0
    assert r.errors == []


def test_ingest_catalog_saves_raws_to_store(tmp_path):
    store = RuleStore(tmp_path)
    raws = [_make_raw("r1"), _make_raw("r2")]
    adapter = _mock_adapter(raws)

    result = ingest_catalog(adapter, store)

    assert result.raw_count == 2
    assert result.failed_count == 0
    loaded = store.load_raw("sigma")
    assert len(loaded) == 2


def test_ingest_catalog_calls_load_once(tmp_path):
    store = RuleStore(tmp_path)
    adapter = _mock_adapter([_make_raw()])

    ingest_catalog(adapter, store)

    adapter.load.assert_called_once()


def test_ingest_catalog_load_failure_returns_error(tmp_path):
    store = RuleStore(tmp_path)
    adapter = _mock_adapter([])
    adapter.load.side_effect = RuntimeError("network error")

    result = ingest_catalog(adapter, store)

    assert result.raw_count == 0
    assert len(result.errors) == 1
    assert "network error" in result.errors[0]


def test_ingest_catalog_empty_load_returns_zero_count(tmp_path):
    store = RuleStore(tmp_path)
    adapter = _mock_adapter([])

    result = ingest_catalog(adapter, store)

    assert result.raw_count == 0
    assert result.errors == []
