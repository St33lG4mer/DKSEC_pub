# tests/storage/test_rule_store.py
import json
from pathlib import Path

from core.ast_model import Condition, RuleAST
from storage.rule_store import RuleStore


def _make_rule(rule_id: str = "rule-1", catalog: str = "sigma") -> RuleAST:
    return RuleAST(
        id=rule_id,
        catalog=catalog,
        name="Test Rule",
        description="",
        severity="high",
        mitre_techniques=["attack.t1059"],
        event_categories=["process"],
        conditions=[
            Condition(field="process.name", raw_field="Image", operator="==",
                      values=["cmd.exe"], raw_values=["cmd.exe"])
        ],
        raw_query='process where process.name == "cmd.exe"',
        language="eql",
        translated_query='process where process.name == "cmd.exe"',
        source_path="/rules/test.yml",
        metadata={},
    )


def test_rule_store_save_and_load(tmp_path):
    store = RuleStore(base_dir=tmp_path)
    rule = _make_rule()
    store.save(rule)

    loaded = store.load("rule-1", "sigma")
    assert loaded.id == "rule-1"
    assert loaded.catalog == "sigma"
    assert loaded.name == "Test Rule"


def test_rule_store_load_all(tmp_path):
    store = RuleStore(base_dir=tmp_path)
    store.save(_make_rule("r1", "sigma"))
    store.save(_make_rule("r2", "sigma"))
    store.save(_make_rule("r3", "elastic"))

    sigma_rules = store.load_all("sigma")
    assert len(sigma_rules) == 2
    assert all(r.catalog == "sigma" for r in sigma_rules)


def test_rule_store_path_structure(tmp_path):
    store = RuleStore(base_dir=tmp_path)
    rule = _make_rule("my-rule", "sigma")
    store.save(rule)

    expected_path = tmp_path / "sigma" / "ast" / "my-rule.json"
    assert expected_path.exists()
    data = json.loads(expected_path.read_text())
    assert data["id"] == "my-rule"


def test_rule_store_load_missing_raises(tmp_path):
    store = RuleStore(base_dir=tmp_path)
    import pytest
    with pytest.raises(FileNotFoundError):
        store.load("nonexistent", "sigma")


def test_rule_store_list_catalogs(tmp_path):
    store = RuleStore(base_dir=tmp_path)
    store.save(_make_rule("r1", "sigma"))
    store.save(_make_rule("r2", "elastic"))

    catalogs = store.list_catalogs()
    assert set(catalogs) == {"sigma", "elastic"}


# --- save_raw / load_raw tests ---

def test_save_raw_creates_file(tmp_path):
    store = RuleStore(tmp_path)
    raws = [{"id": "r1", "title": "Rule 1"}, {"id": "r2", "title": "Rule 2"}]
    path = store.save_raw("sigma", raws)
    assert path.exists()
    assert path.name == "rules.json"


def test_load_raw_returns_saved_data(tmp_path):
    store = RuleStore(tmp_path)
    raws = [{"id": "r1", "title": "Rule 1"}]
    store.save_raw("sigma", raws)
    loaded = store.load_raw("sigma")
    assert loaded == raws


def test_load_raw_returns_empty_when_missing(tmp_path):
    store = RuleStore(tmp_path)
    result = store.load_raw("nonexistent")
    assert result == []
