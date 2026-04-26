"""
Integration tests: ingest → translate → compare → decide full pipeline.
No live SIEM or git repo — all I/O through tmp_path stores.
"""
from unittest.mock import MagicMock

import pytest

from adapters.base import BaseAdapter
from core.ast_model import RuleAST
from pipeline.ingest import ingest_catalog
from pipeline.translate import translate_catalog
from pipeline.compare import compare_rules
from pipeline.decide import decide
from storage.rule_store import RuleStore


def _make_raw(rule_id: str) -> dict:
    return {"id": rule_id, "title": f"Rule {rule_id}", "text": "..."}


def _make_ast(rule_id: str, catalog: str = "sigma", translated: str | None = None, mitre_techniques: list[str] | None = None, event_categories: list[str] | None = None) -> RuleAST:
    return RuleAST(
        id=rule_id,
        catalog=catalog,
        name=f"Rule {rule_id}",
        description="",
        severity="medium",
        mitre_techniques=mitre_techniques or ["attack.t1059.001"],
        event_categories=event_categories or ["process"],
        conditions=[],
        raw_query="any where true",
        language="sigma",
        translated_query=translated or f"process where process.name == '{rule_id}.exe'",
        source_path="test/rule.yml",
    )


def _mock_adapter(raws: list[dict], asts: list[RuleAST], name: str = "sigma") -> BaseAdapter:
    adapter = MagicMock(spec=BaseAdapter)
    adapter.name = name
    adapter.load.return_value = raws
    adapter.parse.side_effect = list(asts)   # consume one per call
    adapter.translate.side_effect = lambda a: a
    return adapter


def test_ingest_then_translate_produces_loadable_asts(tmp_path):
    store = RuleStore(tmp_path)
    raws = [_make_raw("r1"), _make_raw("r2")]
    asts = [_make_ast("r1"), _make_ast("r2")]
    adapter = _mock_adapter(raws, asts)

    ingest_catalog(adapter, store)
    translate_catalog(adapter, store)

    loaded = store.load_all("sigma")
    assert len(loaded) == 2
    ids = {r.id for r in loaded}
    assert "r1" in ids and "r2" in ids


def test_ingest_translate_compare_pipeline(tmp_path):
    store = RuleStore(tmp_path)

    # Sigma: r1 has unique event category (file); r2 overlaps with elastic's e1 (process)
    sigma_raws = [_make_raw("r1"), _make_raw("r2")]
    sigma_asts = [
        _make_ast("r1", "sigma", translated="file where file.name == 'unique.txt'", mitre_techniques=["attack.t1106"], event_categories=["file"]),
        _make_ast("r2", "sigma", translated="process where process.name == 'cmd.exe'", mitre_techniques=["attack.t1059.001"], event_categories=["process"]),
    ]
    sigma_adapter = _mock_adapter(sigma_raws, sigma_asts, name="sigma")

    elastic_raws = [_make_raw("e1")]
    elastic_asts = [_make_ast("e1", "elastic", translated="process where process.name == 'cmd.exe'", mitre_techniques=["attack.t1059.001"], event_categories=["process"])]
    elastic_adapter = _mock_adapter(elastic_raws, elastic_asts, name="elastic")

    ingest_catalog(sigma_adapter, store)
    translate_catalog(sigma_adapter, store)
    ingest_catalog(elastic_adapter, store)
    translate_catalog(elastic_adapter, store)

    sigma_rules = store.load_all("sigma")
    elastic_rules = store.load_all("elastic")

    result = compare_rules(sigma_rules, elastic_rules)

    assert result.catalog_a == "sigma"
    assert result.catalog_b == "elastic"
    # r1 should be unique (different event category - file vs process)
    unique_ids = {r.id for r in result.unique_a}
    assert "r1" in unique_ids


def test_ingest_translate_decide_pipeline(tmp_path):
    store = RuleStore(tmp_path)

    # sigma r1 is unique vs elastic e1 (different event categories: file vs process)
    sigma_raws = [_make_raw("r1")]
    sigma_asts = [_make_ast("r1", "sigma", translated="file where file.name == 'unique.txt'", mitre_techniques=["attack.t1106"], event_categories=["file"])]
    sigma_adapter = _mock_adapter(sigma_raws, sigma_asts, name="sigma")

    elastic_raws = [_make_raw("e1")]
    elastic_asts = [_make_ast("e1", "elastic", translated="process where process.name == 'elastic.exe'", mitre_techniques=["attack.t1059.001"], event_categories=["process"])]
    elastic_adapter = _mock_adapter(elastic_raws, elastic_asts, name="elastic")

    ingest_catalog(sigma_adapter, store)
    translate_catalog(sigma_adapter, store)
    ingest_catalog(elastic_adapter, store)
    translate_catalog(elastic_adapter, store)

    sigma_rules = store.load_all("sigma")
    elastic_rules = store.load_all("elastic")

    compare_result = compare_rules(sigma_rules, elastic_rules)
    decisions = decide(compare_result)

    # r1 is unique → ADD
    assert decisions.get("r1") == "ADD"
