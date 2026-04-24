# tests/adapters/sigma/test_sigma_adapter.py
"""Tests for SigmaAdapter.load() and SigmaAdapter.parse()."""
import pytest
from pathlib import Path
from unittest.mock import patch

from adapters.sigma.adapter import SigmaAdapter
from core.ast_model import RuleAST

SAMPLE_SIGMA_YAML = """\
title: Test Sigma Rule
id: 12345678-1234-1234-1234-123456789012
status: test
description: A test sigma rule
level: high
tags:
  - attack.t1059.001
  - attack.execution
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\cmd.exe'
  condition: selection
"""


# ---------------------------------------------------------------------------
# load() tests
# ---------------------------------------------------------------------------

def test_load_reads_yml_files(tmp_path):
    (tmp_path / "rule1.yml").write_text(SAMPLE_SIGMA_YAML, encoding="utf-8")
    adapter = SigmaAdapter(folder_path=tmp_path)
    raw_rules = adapter.load()
    assert len(raw_rules) == 1
    assert raw_rules[0]["meta"]["title"] == "Test Sigma Rule"


def test_load_skips_unsupported_status(tmp_path):
    experimental = SAMPLE_SIGMA_YAML.replace("status: test", "status: experimental")
    (tmp_path / "experimental.yml").write_text(experimental, encoding="utf-8")
    adapter = SigmaAdapter(folder_path=tmp_path)
    raw_rules = adapter.load()
    assert len(raw_rules) == 0


def test_load_custom_status_filter(tmp_path):
    stable = SAMPLE_SIGMA_YAML.replace("status: test", "status: stable")
    experimental = SAMPLE_SIGMA_YAML.replace("status: test", "status: experimental")
    (tmp_path / "stable.yml").write_text(stable, encoding="utf-8")
    (tmp_path / "exp.yml").write_text(experimental, encoding="utf-8")
    adapter = SigmaAdapter(folder_path=tmp_path, status_filter={"stable", "experimental"})
    raw_rules = adapter.load()
    assert len(raw_rules) == 2


def test_load_skips_invalid_yaml(tmp_path):
    (tmp_path / "bad.yml").write_text("not: valid: yaml:::", encoding="utf-8")
    (tmp_path / "good.yml").write_text(SAMPLE_SIGMA_YAML, encoding="utf-8")
    adapter = SigmaAdapter(folder_path=tmp_path)
    raw_rules = adapter.load()
    assert len(raw_rules) == 1


def test_load_raises_when_folder_missing():
    adapter = SigmaAdapter(folder_path="/nonexistent/path/that/does/not/exist")
    with pytest.raises(FileNotFoundError):
        adapter.load()


def test_load_returns_path_text_meta_keys(tmp_path):
    (tmp_path / "rule1.yml").write_text(SAMPLE_SIGMA_YAML, encoding="utf-8")
    adapter = SigmaAdapter(folder_path=tmp_path)
    raw_rules = adapter.load()
    assert "path" in raw_rules[0]
    assert "text" in raw_rules[0]
    assert "meta" in raw_rules[0]


# ---------------------------------------------------------------------------
# parse() tests
# ---------------------------------------------------------------------------

def _make_raw(tmp_path: Path, *, level="high", id_val="abc-123", tags=None, logsource=None) -> dict:
    return {
        "path": str(tmp_path / "rule.yml"),
        "text": SAMPLE_SIGMA_YAML,
        "meta": {
            "title": "Test Sigma Rule",
            "id": id_val,
            "description": "A test sigma rule",
            "level": level,
            "tags": tags if tags is not None else ["attack.t1059.001", "attack.execution"],
            "status": "test",
            "logsource": logsource if logsource is not None else {"category": "process_creation", "product": "windows"},
            "author": "Test Author",
        },
    }


def test_parse_returns_rule_ast(tmp_path):
    adapter = SigmaAdapter(folder_path=tmp_path)
    rule = adapter.parse(_make_raw(tmp_path))
    assert isinstance(rule, RuleAST)


def test_parse_catalog_is_sigma(tmp_path):
    adapter = SigmaAdapter(folder_path=tmp_path)
    rule = adapter.parse(_make_raw(tmp_path))
    assert rule.catalog == "sigma"


def test_parse_name_from_title(tmp_path):
    adapter = SigmaAdapter(folder_path=tmp_path)
    rule = adapter.parse(_make_raw(tmp_path))
    assert rule.name == "Test Sigma Rule"


def test_parse_uses_sigma_id(tmp_path):
    adapter = SigmaAdapter(folder_path=tmp_path)
    rule = adapter.parse(_make_raw(tmp_path, id_val="abc-123"))
    assert rule.id == "abc-123"


def test_parse_generates_uuid_when_id_missing(tmp_path):
    adapter = SigmaAdapter(folder_path=tmp_path)
    raw = _make_raw(tmp_path)
    del raw["meta"]["id"]
    rule = adapter.parse(raw)
    assert len(rule.id) == 36  # UUID4 format


def test_parse_severity_mapping(tmp_path):
    adapter = SigmaAdapter(folder_path=tmp_path)
    for level, expected in [
        ("critical", "critical"),
        ("high", "high"),
        ("medium", "medium"),
        ("low", "low"),
        ("informational", "low"),
    ]:
        rule = adapter.parse(_make_raw(tmp_path, level=level))
        assert rule.severity == expected, f"level={level} should map to {expected}"


def test_parse_extracts_mitre_techniques(tmp_path):
    adapter = SigmaAdapter(folder_path=tmp_path)
    rule = adapter.parse(_make_raw(tmp_path, tags=["attack.t1059.001", "attack.execution"]))
    assert "attack.t1059.001" in rule.mitre_techniques
    # Tactics (non-technique attack.* tags) are NOT in mitre_techniques
    assert "attack.execution" not in rule.mitre_techniques


def test_parse_event_categories_from_logsource(tmp_path):
    adapter = SigmaAdapter(folder_path=tmp_path)
    rule = adapter.parse(_make_raw(tmp_path, logsource={"category": "process_creation", "product": "windows"}))
    assert "process_creation" in rule.event_categories


def test_parse_language_is_sigma(tmp_path):
    adapter = SigmaAdapter(folder_path=tmp_path)
    rule = adapter.parse(_make_raw(tmp_path))
    assert rule.language == "sigma"


def test_parse_translated_query_is_none(tmp_path):
    adapter = SigmaAdapter(folder_path=tmp_path)
    rule = adapter.parse(_make_raw(tmp_path))
    assert rule.translated_query is None


def test_parse_raw_query_is_yaml_text(tmp_path):
    adapter = SigmaAdapter(folder_path=tmp_path)
    raw = _make_raw(tmp_path)
    rule = adapter.parse(raw)
    assert rule.raw_query == raw["text"]


def test_parse_metadata_contains_author(tmp_path):
    adapter = SigmaAdapter(folder_path=tmp_path)
    rule = adapter.parse(_make_raw(tmp_path))
    assert rule.metadata.get("author") == "Test Author"
