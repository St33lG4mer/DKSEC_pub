# tests/storage/test_result_store.py
import json
from pathlib import Path

from storage.result_store import ResultStore


def test_result_store_save_and_load_overlaps(tmp_path):
    store = ResultStore(base_dir=tmp_path)
    overlaps = [
        {"sigma_id": "r1", "elastic_id": "e1", "jaccard": 0.6, "confidence": "logic+alerts"},
        {"sigma_id": "r2", "elastic_id": "e2", "jaccard": 0.3, "confidence": "logic-only"},
    ]
    store.save_overlaps("sigma", "elastic", overlaps)
    loaded = store.load_overlaps("sigma", "elastic")
    assert len(loaded) == 2
    assert loaded[0]["sigma_id"] == "r1"


def test_result_store_save_and_load_unique(tmp_path):
    store = ResultStore(base_dir=tmp_path)
    unique = [{"id": "r3", "catalog": "sigma", "name": "Unique Rule"}]
    store.save_unique("sigma", "elastic", unique)
    loaded = store.load_unique("sigma", "elastic")
    assert len(loaded) == 1
    assert loaded[0]["id"] == "r3"


def test_result_store_save_and_load_decisions(tmp_path):
    store = ResultStore(base_dir=tmp_path)
    decisions = {"r1": "SKIP", "r3": "ADD"}
    store.save_decisions("sigma", "elastic", decisions)
    loaded = store.load_decisions("sigma", "elastic")
    assert loaded["r1"] == "SKIP"
    assert loaded["r3"] == "ADD"


def test_result_store_path_structure(tmp_path):
    store = ResultStore(base_dir=tmp_path)
    store.save_overlaps("sigma", "elastic", [])
    expected = tmp_path / "overlaps" / "sigma_vs_elastic.json"
    assert expected.exists()
