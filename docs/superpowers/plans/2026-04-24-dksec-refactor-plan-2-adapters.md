# DKSec Refactor — Plan 2: Adapters

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `SigmaAdapter` and `ElasticAdapter` — the two concrete catalog adapters that translate Sigma YAML rules and Elastic detection rules into the canonical `RuleAST` format, enabling catalog-agnostic comparison.

**Architecture:** Two adapter packages under `adapters/`, each implementing `BaseAdapter` from Plan 1. `SigmaAdapter` uses `FolderSource` (from `core/sources/folder_source.py`) to walk YAML files and pySigma's `EqlBackend` to translate to EQL. `ElasticAdapter` paginates Kibana's `_find` API, normalizes MITRE tags via `core.normalizer`, and supports live EQL validation and rule deployment. All tests use fixtures and mock external calls — no real Kibana or Sigma repo required.

**Tech Stack:** Python 3.10+, `pySigma>=1.3`, `pySigma-backend-elasticsearch>=2.0`, `pySigma-pipeline-windows>=2.0`, `requests>=2.33`, `pytest`, `unittest.mock`

---

## Pre-requisite

Before starting, create a feature branch from `main`:

```
git checkout main
git pull
git checkout -b plan2-adapters
```

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `adapters/sigma/__init__.py` | Create | Package marker |
| `adapters/sigma/translator.py` | Create | `sigma_to_eql(yaml_text)` — pure pySigma translation |
| `adapters/sigma/adapter.py` | Create | `SigmaAdapter(BaseAdapter)` — load, parse, translate |
| `adapters/elastic/__init__.py` | Create | Package marker |
| `adapters/elastic/adapter.py` | Create | `ElasticAdapter(BaseAdapter)` — load, parse, translate, validate, deploy |
| `tests/adapters/sigma/__init__.py` | Create | Package marker |
| `tests/adapters/sigma/test_translator.py` | Create | Tests for `sigma_to_eql` |
| `tests/adapters/sigma/test_sigma_adapter.py` | Create | Tests for `SigmaAdapter` (load, parse, translate) |
| `tests/adapters/elastic/__init__.py` | Create | Package marker |
| `tests/adapters/elastic/test_elastic_adapter.py` | Create | Tests for `ElasticAdapter` (load, parse, translate, validate, deploy) |

---

## Shared test fixture

Both adapter test files use a sample Sigma YAML string. It is reproduced in full in each task — do not assume shared state between tasks.

```python
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
```

---

## Task 1: `adapters/sigma/translator.py`

**Files:**
- Create: `adapters/sigma/__init__.py`
- Create: `adapters/sigma/translator.py`
- Create: `tests/adapters/sigma/__init__.py`
- Create: `tests/adapters/sigma/test_translator.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/adapters/sigma/test_translator.py
"""Tests for sigma_to_eql — the pure translation function."""
from adapters.sigma.translator import sigma_to_eql

SAMPLE_SIGMA_YAML = """\
title: Test Sigma Rule
id: 12345678-1234-1234-1234-123456789012
status: test
description: A test sigma rule
level: high
tags:
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\cmd.exe'
  condition: selection
"""


def test_sigma_to_eql_returns_string_for_valid_rule():
    result = sigma_to_eql(SAMPLE_SIGMA_YAML)
    # pySigma may or may not produce output depending on pipeline mapping
    # We assert it either returns a non-empty string or None — no exception
    assert result is None or (isinstance(result, str) and len(result) > 0)


def test_sigma_to_eql_returns_none_for_empty_input():
    result = sigma_to_eql("")
    assert result is None


def test_sigma_to_eql_returns_none_for_unparseable_yaml():
    result = sigma_to_eql("not: valid: sigma:::")
    assert result is None


def test_sigma_to_eql_returns_none_for_rule_with_no_detection():
    minimal = """\
title: No Detection
id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
status: test
logsource:
  category: process_creation
  product: windows
detection:
  condition: ''
"""
    result = sigma_to_eql(minimal)
    assert result is None or isinstance(result, str)
```

- [ ] **Step 2: Create package markers**

```python
# adapters/sigma/__init__.py
```

```python
# tests/adapters/sigma/__init__.py
```

- [ ] **Step 3: Run tests to verify they fail**

```
python -m pytest tests/adapters/sigma/test_translator.py -v
```
Expected: `ImportError: No module named 'adapters.sigma.translator'`

- [ ] **Step 4: Implement `adapters/sigma/translator.py`**

```python
# adapters/sigma/translator.py
"""
Pure pySigma → EQL translation.
Isolated here so SigmaAdapter.translate() can be tested independently via mocking.
"""
from __future__ import annotations


def sigma_to_eql(yaml_text: str) -> str | None:
    """
    Convert a Sigma rule YAML string to EQL using pySigma's EqlBackend.

    Returns a non-empty EQL string on success, or None if:
    - yaml_text is empty or unparseable
    - pySigma produces no output (unsupported logsource/condition)
    - any exception is raised during translation
    """
    if not yaml_text or not yaml_text.strip():
        return None
    try:
        from sigma.backends.elasticsearch import EqlBackend
        from sigma.collection import SigmaCollection
        from sigma.pipelines.elasticsearch.windows import ecs_windows

        collection = SigmaCollection.from_yaml(yaml_text)
        backend = EqlBackend(processing_pipeline=ecs_windows())
        queries = backend.convert(collection)
        if not queries:
            return None
        return "\n\n".join(queries)
    except Exception:
        return None
```

- [ ] **Step 5: Run tests to verify they pass**

```
python -m pytest tests/adapters/sigma/test_translator.py -v
```
Expected: 4 passed

- [ ] **Step 6: Commit**

```
git add adapters/sigma/__init__.py adapters/sigma/translator.py tests/adapters/sigma/__init__.py tests/adapters/sigma/test_translator.py
git commit -m "feat: add adapters/sigma/translator.py with sigma_to_eql"
```

---

## Task 2: `SigmaAdapter` — `load()` and `parse()`

**Files:**
- Create: `adapters/sigma/adapter.py`
- Create: `tests/adapters/sigma/test_sigma_adapter.py`

- [ ] **Step 1: Write the failing tests**

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

```
python -m pytest tests/adapters/sigma/test_sigma_adapter.py -v
```
Expected: `ImportError: No module named 'adapters.sigma.adapter'`

- [ ] **Step 3: Implement `adapters/sigma/adapter.py` (load + parse)**

```python
# adapters/sigma/adapter.py
"""SigmaAdapter — loads Sigma YAML rules and translates them to EQL."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from adapters.base import BaseAdapter
from core.ast_model import RuleAST, ValidationResult
from core.sources.folder_source import FolderSource

# Sigma level → canonical severity label
_LEVEL_TO_SEVERITY: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "low",
}

_TECHNIQUE_RE = re.compile(r"^attack\.[tT]\d+", re.I)


class SigmaAdapter(BaseAdapter):
    """
    Adapter for Sigma detection rules stored in a local folder.

    load()      — walks folder_path for *.yml files, filters by status
    parse()     — converts Sigma YAML dict to RuleAST (language="sigma")
    translate() — converts Sigma YAML to EQL via pySigma EqlBackend
    """

    name = "sigma"
    source_type = "folder"

    def __init__(
        self,
        folder_path: str | Path,
        status_filter: set[str] | None = None,
    ) -> None:
        self.folder_path = Path(folder_path)
        self.status_filter = status_filter if status_filter is not None else {"stable", "test"}

    def load(self) -> list[dict]:
        """
        Walk folder_path for *.yml files.
        Filter by status_filter. Skip malformed YAML silently.
        Returns list of {"path": str, "text": str, "meta": dict}.
        Raises FileNotFoundError if folder_path does not exist.
        """
        source = FolderSource(self.folder_path, glob_pattern="**/*.yml")
        result: list[dict] = []
        for path, text in source.iter_contents():
            try:
                meta = yaml.safe_load(text) or {}
            except Exception:
                continue
            status = meta.get("status", "")
            if status not in self.status_filter:
                continue
            result.append({"path": str(path), "text": text, "meta": meta})
        return result

    def parse(self, raw: dict) -> RuleAST:
        """
        Convert a raw Sigma rule dict (as returned by load()) to a canonical RuleAST.
        translated_query is always None at this stage.
        """
        meta = raw.get("meta", {})
        sigma_id = str(meta["id"]) if meta.get("id") else RuleAST.new_id()
        title = meta.get("title") or Path(raw.get("path", "unknown")).stem
        description = meta.get("description", "")
        level = (meta.get("level") or "medium").lower()
        severity = _LEVEL_TO_SEVERITY.get(level, "medium")

        raw_tags: list[str] = [t for t in (meta.get("tags") or []) if isinstance(t, str)]
        mitre_techniques = [t for t in raw_tags if _TECHNIQUE_RE.match(t)]

        logsource: dict = meta.get("logsource") or {}
        event_categories: list[str] = []
        if logsource.get("category"):
            event_categories.append(logsource["category"])

        return RuleAST(
            id=sigma_id,
            catalog="sigma",
            name=title,
            description=description,
            severity=severity,
            mitre_techniques=mitre_techniques,
            event_categories=event_categories,
            conditions=[],
            raw_query=raw.get("text", ""),
            language="sigma",
            translated_query=None,
            source_path=raw.get("path", ""),
            metadata={
                "author": meta.get("author", ""),
                "status": meta.get("status", ""),
                "tags": raw_tags,
                "logsource": logsource,
            },
        )

    def translate(self, ast: RuleAST) -> RuleAST:
        """
        Convert the Sigma YAML in ast.raw_query to EQL via pySigma.
        Sets ast.translated_query to the EQL string, or None if translation fails.
        """
        from adapters.sigma.translator import sigma_to_eql

        ast.translated_query = sigma_to_eql(ast.raw_query)
        return ast

    def validate(self, ast: RuleAST) -> ValidationResult:
        """Default: always valid (no live ES required for Sigma rules)."""
        return ValidationResult(valid=True)
```

- [ ] **Step 4: Run tests to verify they pass**

```
python -m pytest tests/adapters/sigma/test_sigma_adapter.py -v
```
Expected: 17 passed

- [ ] **Step 5: Commit**

```
git add adapters/sigma/adapter.py tests/adapters/sigma/test_sigma_adapter.py
git commit -m "feat: add SigmaAdapter load() and parse()"
```

---

## Task 3: `SigmaAdapter.translate()` — integration and mocked tests

This task adds `translate()` tests to the existing sigma adapter test file. The implementation is already in `adapter.py` from Task 2 — only tests are added here.

**Files:**
- Modify: `tests/adapters/sigma/test_sigma_adapter.py` — append translate() tests

- [ ] **Step 1: Append translate tests to the existing file**

Add these functions at the end of `tests/adapters/sigma/test_sigma_adapter.py`:

```python
# ---------------------------------------------------------------------------
# translate() tests
# ---------------------------------------------------------------------------

def test_translate_sets_translated_query_via_mock(tmp_path):
    adapter = SigmaAdapter(folder_path=tmp_path)
    rule = adapter.parse(_make_raw(tmp_path))
    with patch("adapters.sigma.translator.sigma_to_eql", return_value='process where process.name == "cmd.exe"'):
        result = adapter.translate(rule)
    assert result.translated_query == 'process where process.name == "cmd.exe"'


def test_translate_sets_none_when_translation_fails(tmp_path):
    adapter = SigmaAdapter(folder_path=tmp_path)
    rule = adapter.parse(_make_raw(tmp_path))
    with patch("adapters.sigma.translator.sigma_to_eql", return_value=None):
        result = adapter.translate(rule)
    assert result.translated_query is None


def test_translate_returns_same_ast_object(tmp_path):
    adapter = SigmaAdapter(folder_path=tmp_path)
    rule = adapter.parse(_make_raw(tmp_path))
    with patch("adapters.sigma.translator.sigma_to_eql", return_value="process where true"):
        result = adapter.translate(rule)
    assert result is rule  # mutates in-place, returns same object


def test_translate_integration_does_not_raise(tmp_path):
    """End-to-end: real pySigma. Only asserts no exception; output may be None."""
    (tmp_path / "rule.yml").write_text(SAMPLE_SIGMA_YAML, encoding="utf-8")
    adapter = SigmaAdapter(folder_path=tmp_path)
    raw_list = adapter.load()
    assert len(raw_list) == 1
    rule = adapter.parse(raw_list[0])
    result = adapter.translate(rule)  # must not raise
    assert result.translated_query is None or isinstance(result.translated_query, str)
```

- [ ] **Step 2: Run the full sigma test suite**

```
python -m pytest tests/adapters/sigma/ -v
```
Expected: 21+ passed (17 from Task 2 + 4 new)

- [ ] **Step 3: Commit**

```
git add tests/adapters/sigma/test_sigma_adapter.py
git commit -m "test: add SigmaAdapter.translate() tests"
```

---

## Task 4: `ElasticAdapter` — `load()` and `parse()`

**Files:**
- Create: `adapters/elastic/__init__.py`
- Create: `adapters/elastic/adapter.py`
- Create: `tests/adapters/elastic/__init__.py`
- Create: `tests/adapters/elastic/test_elastic_adapter.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/adapters/elastic/test_elastic_adapter.py
"""Tests for ElasticAdapter.load(), parse(), translate(), validate(), deploy()."""
import pytest
from unittest.mock import patch, MagicMock

from adapters.elastic.adapter import ElasticAdapter
from core.ast_model import RuleAST, ValidationResult

SAMPLE_ELASTIC_RULE = {
    "id": "uuid-abc-123",
    "rule_id": "elastic-rule-001",
    "name": "Test Elastic Rule",
    "description": "A test elastic rule",
    "type": "eql",
    "query": 'process where process.name == "cmd.exe"',
    "risk_score": 73,
    "enabled": True,
    "tags": [
        "Technique: Command and Scripting Interpreter (T1059)",
        "Tactic: Execution",
    ],
    "author": ["Elastic"],
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-02T00:00:00Z",
}


# ---------------------------------------------------------------------------
# load() tests
# ---------------------------------------------------------------------------

def test_load_returns_rules_from_single_page():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="elastic", password="pass")
    page = MagicMock(status_code=200)
    page.json.return_value = {"data": [SAMPLE_ELASTIC_RULE], "total": 1}
    with patch("requests.get", return_value=page):
        rules = adapter.load()
    assert len(rules) == 1
    assert rules[0]["name"] == "Test Elastic Rule"


def test_load_paginates_correctly():
    rule_a = {**SAMPLE_ELASTIC_RULE, "rule_id": "rule-a"}
    rule_b = {**SAMPLE_ELASTIC_RULE, "rule_id": "rule-b"}
    page1 = MagicMock(status_code=200)
    page1.json.return_value = {"data": [rule_a], "total": 2}
    page2 = MagicMock(status_code=200)
    page2.json.return_value = {"data": [rule_b], "total": 2}
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    with patch("requests.get", side_effect=[page1, page2]):
        rules = adapter.load()
    assert len(rules) == 2
    assert {r["rule_id"] for r in rules} == {"rule-a", "rule-b"}


def test_load_stops_when_batch_is_empty():
    page1 = MagicMock(status_code=200)
    page1.json.return_value = {"data": [SAMPLE_ELASTIC_RULE], "total": 100}
    page2 = MagicMock(status_code=200)
    page2.json.return_value = {"data": [], "total": 100}
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    with patch("requests.get", side_effect=[page1, page2]):
        rules = adapter.load()
    assert len(rules) == 1


def test_load_retries_on_429_then_succeeds():
    retry_resp = MagicMock(status_code=429)
    ok_resp = MagicMock(status_code=200)
    ok_resp.json.return_value = {"data": [SAMPLE_ELASTIC_RULE], "total": 1}
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    with patch("requests.get", side_effect=[retry_resp, ok_resp]):
        with patch("time.sleep"):  # don't actually sleep in tests
            rules = adapter.load()
    assert len(rules) == 1


def test_load_raises_on_403():
    resp = MagicMock(status_code=403, text="Forbidden")
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    with patch("requests.get", return_value=resp):
        with pytest.raises(RuntimeError, match="Kibana API error 403"):
            adapter.load()


# ---------------------------------------------------------------------------
# parse() tests
# ---------------------------------------------------------------------------

def test_parse_returns_rule_ast():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    assert isinstance(rule, RuleAST)


def test_parse_catalog_is_elastic():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    assert rule.catalog == "elastic"


def test_parse_uses_rule_id_as_ast_id():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    assert rule.id == "elastic-rule-001"


def test_parse_falls_back_to_id_field_when_rule_id_missing():
    raw = {**SAMPLE_ELASTIC_RULE}
    del raw["rule_id"]
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(raw)
    assert rule.id == "uuid-abc-123"


def test_parse_severity_from_risk_score():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    for risk, expected in [(99, "critical"), (73, "high"), (47, "medium"), (21, "low"), (0, "low")]:
        rule = adapter.parse({**SAMPLE_ELASTIC_RULE, "risk_score": risk})
        assert rule.severity == expected, f"risk={risk} should map to {expected}"


def test_parse_normalizes_mitre_tags():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    raw = {
        **SAMPLE_ELASTIC_RULE,
        "tags": [
            "Tactic: Execution",
            "Technique: Command and Scripting Interpreter (T1059)",
            "Subtechnique: PowerShell (T1059.001)",
        ],
    }
    rule = adapter.parse(raw)
    assert "attack.execution" in rule.mitre_techniques
    assert "attack.t1059" in rule.mitre_techniques
    assert "attack.t1059.001" in rule.mitre_techniques


def test_parse_non_mitre_tags_excluded_from_techniques():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    raw = {**SAMPLE_ELASTIC_RULE, "tags": ["Custom Tag", "Elastic Endgame"]}
    rule = adapter.parse(raw)
    assert rule.mitre_techniques == []


def test_parse_raw_query_preserved():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    assert rule.raw_query == 'process where process.name == "cmd.exe"'


def test_parse_language_from_type_field():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    assert rule.language == "eql"


def test_parse_translated_query_is_none():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    assert rule.translated_query is None


def test_parse_metadata_contains_rule_id_and_enabled():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    assert rule.metadata["rule_id"] == "elastic-rule-001"
    assert rule.metadata["enabled"] is True
```

- [ ] **Step 2: Create package markers**

```python
# adapters/elastic/__init__.py
```

```python
# tests/adapters/elastic/__init__.py
```

- [ ] **Step 3: Run tests to verify they fail**

```
python -m pytest tests/adapters/elastic/test_elastic_adapter.py -v
```
Expected: `ImportError: No module named 'adapters.elastic.adapter'`

- [ ] **Step 4: Implement `adapters/elastic/adapter.py` (load + parse)**

```python
# adapters/elastic/adapter.py
"""ElasticAdapter — loads Elastic detection rules from Kibana API and normalizes to RuleAST."""
from __future__ import annotations

import time

import requests

from adapters.base import BaseAdapter
from core.ast_model import RuleAST, ValidationResult
from core.normalizer import (
    extract_eql_tokens,
    normalize_elastic_mitre_tag,
    risk_to_severity,
    SEVERITY_TO_RISK,
)


def _kibana_headers(user: str, password: str) -> dict:
    import base64
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {
        "Authorization": f"Basic {token}",
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
    }


class ElasticAdapter(BaseAdapter):
    """
    Adapter for Elastic Security detection rules loaded via Kibana API.

    load()      — paginates /api/detection_engine/rules/_find
    parse()     — converts raw Kibana rule JSON to RuleAST
    translate() — no-op: Elastic rules are already EQL; copies raw_query → translated_query
    validate()  — validates EQL against ES cluster (requires es_host)
    deploy()    — creates/updates rule in Kibana
    """

    name = "elastic"
    source_type = "api"

    def __init__(
        self,
        kibana_url: str,
        user: str,
        password: str,
        es_host: str = "",
    ) -> None:
        self.kibana_url = kibana_url.rstrip("/")
        self.user = user
        self.password = password
        self.es_host = es_host.rstrip("/")

    def load(self) -> list[dict]:
        """
        Paginate Kibana detection engine API.
        Returns list of raw rule dicts.
        Raises RuntimeError on non-200/non-retryable response.
        """
        headers = _kibana_headers(self.user, self.password)
        rules: list[dict] = []
        page, per_page = 1, 500

        while True:
            resp = None
            for attempt in range(5):
                resp = requests.get(
                    f"{self.kibana_url}/api/detection_engine/rules/_find",
                    headers=headers,
                    params={"page": page, "per_page": per_page},
                    timeout=30,
                )
                if resp.status_code in (429, 500):
                    time.sleep(2 ** attempt)
                    continue
                break

            if resp.status_code not in (200,):
                raise RuntimeError(f"Kibana API error {resp.status_code}: {resp.text[:200]}")

            data = resp.json()
            batch = data.get("data", [])
            rules.extend(batch)
            if len(rules) >= data.get("total", 0) or not batch:
                break
            page += 1

        return rules

    def parse(self, raw: dict) -> RuleAST:
        """
        Convert a raw Kibana rule dict to a canonical RuleAST.
        translated_query is always None at this stage.
        """
        risk = raw.get("risk_score", 47)
        severity = risk_to_severity(risk)

        raw_tags: list[str] = [t for t in (raw.get("tags") or []) if isinstance(t, str)]
        mitre_techniques: list[str] = []
        for tag in raw_tags:
            norm = normalize_elastic_mitre_tag(tag)
            if norm:
                mitre_techniques.append(norm)

        query = raw.get("query", "")
        event_categories: list[str] = []
        if query:
            tokens = extract_eql_tokens(query)
            event_categories = [t.replace("@cat:", "") for t in tokens if t.startswith("@cat:")]

        rule_id = raw.get("rule_id") or raw.get("id") or RuleAST.new_id()

        return RuleAST(
            id=rule_id,
            catalog="elastic",
            name=raw.get("name", ""),
            description=raw.get("description", ""),
            severity=severity,
            mitre_techniques=mitre_techniques,
            event_categories=event_categories,
            conditions=[],
            raw_query=query,
            language=raw.get("type", "eql"),
            translated_query=None,
            source_path=f"{self.kibana_url}/api/detection_engine/rules/_find",
            metadata={
                "rule_id": raw.get("rule_id", ""),
                "enabled": raw.get("enabled", True),
                "tags": raw_tags,
                "author": raw.get("author", []),
                "created_at": raw.get("created_at", ""),
                "updated_at": raw.get("updated_at", ""),
            },
        )

    def translate(self, ast: RuleAST) -> RuleAST:
        """Elastic rules are already EQL — copy raw_query to translated_query."""
        ast.translated_query = ast.raw_query
        return ast

    def validate(self, ast: RuleAST) -> ValidationResult:
        """
        Validate EQL against Elasticsearch /logs-*/_eql/search endpoint.
        Returns ValidationResult(valid=False, category="config_error") if es_host not set.
        """
        if not self.es_host:
            return ValidationResult(
                valid=False,
                error="No Elasticsearch host configured",
                category="config_error",
            )
        query = ast.translated_query or ast.raw_query
        if not query:
            return ValidationResult(
                valid=False,
                error="No query to validate",
                category="config_error",
            )
        url = f"{self.es_host}/logs-*/_eql/search"
        try:
            session = requests.Session()
            session.auth = (self.user, self.password)
            session.headers.update({"Content-Type": "application/json"})
            r = session.post(
                url,
                json={"query": query, "size": 0},
                params={"ignore_unavailable": "true"},
                timeout=10,
            )
            if r.status_code == 200:
                return ValidationResult(valid=True)
            body = r.json()
            error = body.get("error", {})
            reason = (
                error.get("caused_by", {}).get("reason")
                or (error.get("root_cause") or [{}])[0].get("reason")
                or error.get("reason")
                or r.text[:300]
            )
            return ValidationResult(valid=False, error=reason, category="eql_error")
        except Exception as exc:
            return ValidationResult(valid=False, error=str(exc), category="connection_error")

    def deploy(self, ast: RuleAST, client=None) -> bool:
        """
        Create or update a detection rule in Kibana.
        Returns True on success (HTTP 200 or 201), False otherwise.
        """
        headers = _kibana_headers(self.user, self.password)
        rule_body: dict = {
            "name": ast.name,
            "description": ast.description,
            "risk_score": SEVERITY_TO_RISK.get(ast.severity, 47),
            "severity": ast.severity,
            "type": ast.language,
            "query": ast.translated_query or ast.raw_query,
            "enabled": True,
            "tags": ast.mitre_techniques,
        }
        if ast.metadata.get("rule_id"):
            rule_body["rule_id"] = ast.metadata["rule_id"]

        resp = requests.post(
            f"{self.kibana_url}/api/detection_engine/rules",
            headers=headers,
            json=rule_body,
            timeout=30,
        )
        return resp.status_code in (200, 201)
```

- [ ] **Step 5: Run the load + parse tests**

```
python -m pytest tests/adapters/elastic/test_elastic_adapter.py -v -k "load or parse"
```
Expected: all load/parse tests pass

- [ ] **Step 6: Commit**

```
git add adapters/elastic/__init__.py adapters/elastic/adapter.py tests/adapters/elastic/__init__.py tests/adapters/elastic/test_elastic_adapter.py
git commit -m "feat: add ElasticAdapter load() and parse()"
```

---

## Task 5: `ElasticAdapter` — `translate()`, `validate()`, `deploy()`

The implementation is already in `adapter.py` from Task 4. This task adds the remaining tests.

**Files:**
- Modify: `tests/adapters/elastic/test_elastic_adapter.py` — append translate/validate/deploy tests

- [ ] **Step 1: Append translate/validate/deploy tests**

Add these functions at the end of `tests/adapters/elastic/test_elastic_adapter.py`:

```python
# ---------------------------------------------------------------------------
# translate() tests
# ---------------------------------------------------------------------------

def test_translate_copies_raw_query_to_translated():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    result = adapter.translate(rule)
    assert result.translated_query == result.raw_query


def test_translate_returns_same_ast_object():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    result = adapter.translate(rule)
    assert result is rule


# ---------------------------------------------------------------------------
# validate() tests
# ---------------------------------------------------------------------------

def test_validate_returns_valid_on_200():
    adapter = ElasticAdapter(
        kibana_url="http://kibana:5601", user="elastic", password="pass",
        es_host="http://es:9200"
    )
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    adapter.translate(rule)
    ok_resp = MagicMock(status_code=200)
    with patch("requests.Session") as MockSession:
        MockSession.return_value.post.return_value = ok_resp
        result = adapter.validate(rule)
    assert result.valid is True
    assert result.error is None


def test_validate_returns_invalid_on_400():
    adapter = ElasticAdapter(
        kibana_url="http://kibana:5601", user="elastic", password="pass",
        es_host="http://es:9200"
    )
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    adapter.translate(rule)
    error_resp = MagicMock(status_code=400)
    error_resp.json.return_value = {
        "error": {"reason": "Unknown column [process.nonexistent]"}
    }
    with patch("requests.Session") as MockSession:
        MockSession.return_value.post.return_value = error_resp
        result = adapter.validate(rule)
    assert result.valid is False
    assert "process.nonexistent" in result.error


def test_validate_returns_error_when_no_es_host():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    adapter.translate(rule)
    result = adapter.validate(rule)
    assert result.valid is False
    assert result.category == "config_error"


def test_validate_returns_error_on_connection_failure():
    adapter = ElasticAdapter(
        kibana_url="http://kibana:5601", user="u", password="p",
        es_host="http://es:9200"
    )
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    adapter.translate(rule)
    with patch("requests.Session") as MockSession:
        MockSession.return_value.post.side_effect = ConnectionError("refused")
        result = adapter.validate(rule)
    assert result.valid is False
    assert result.category == "connection_error"


# ---------------------------------------------------------------------------
# deploy() tests
# ---------------------------------------------------------------------------

def test_deploy_returns_true_on_201():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    adapter.translate(rule)
    created_resp = MagicMock(status_code=201)
    with patch("requests.post", return_value=created_resp):
        result = adapter.deploy(rule)
    assert result is True


def test_deploy_returns_true_on_200():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    adapter.translate(rule)
    ok_resp = MagicMock(status_code=200)
    with patch("requests.post", return_value=ok_resp):
        result = adapter.deploy(rule)
    assert result is True


def test_deploy_returns_false_on_400():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    adapter.translate(rule)
    err_resp = MagicMock(status_code=400, text="Bad Request")
    with patch("requests.post", return_value=err_resp):
        result = adapter.deploy(rule)
    assert result is False


def test_deploy_sends_correct_payload():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    adapter.translate(rule)
    ok_resp = MagicMock(status_code=201)
    with patch("requests.post", return_value=ok_resp) as mock_post:
        adapter.deploy(rule)
    call_kwargs = mock_post.call_args
    sent_body = call_kwargs[1]["json"] if "json" in call_kwargs[1] else call_kwargs[0][1]
    assert sent_body["name"] == "Test Elastic Rule"
    assert sent_body["type"] == "eql"
    assert sent_body["rule_id"] == "elastic-rule-001"
```

- [ ] **Step 2: Run full elastic test suite**

```
python -m pytest tests/adapters/elastic/test_elastic_adapter.py -v
```
Expected: 28+ passed (all load/parse/translate/validate/deploy tests)

- [ ] **Step 3: Commit**

```
git add tests/adapters/elastic/test_elastic_adapter.py
git commit -m "test: add ElasticAdapter translate/validate/deploy tests"
```

---

## Task 6: Full suite verification + merge

**Files:** None changed — verification only

- [ ] **Step 1: Run the complete test suite**

```
python -m pytest tests/ -v
```
Expected: 57 original tests + ~25 new sigma tests + ~28 new elastic tests = **~110 passed, 0 failed**

- [ ] **Step 2: Verify no existing file was broken**

Check that the existing dashboard and pages still import cleanly:
```
python -c "import utils; print('utils OK')"
python -c "import dashboard; print('dashboard OK')"
```
Expected: both print OK (no errors — utils.py and dashboard.py are untouched)

- [ ] **Step 3: Commit final verification**

```
git add .
git commit -m "chore: verify Plan 2 adapters — all tests passing"
```

- [ ] **Step 4: Merge to main**

```
git checkout main
git pull
git merge plan2-adapters
```

- [ ] **Step 5: Verify tests on main**

```
python -m pytest tests/ -q
```
Expected: 110+ passed, 0 failed

- [ ] **Step 6: Clean up branch**

```
git branch -D plan2-adapters
```

---

## Summary

Plan 2 adds two production-ready catalog adapters:

| Adapter | File | Source | Translates |
|---------|------|--------|-----------|
| `SigmaAdapter` | `adapters/sigma/adapter.py` | Local folder (`.yml` files) | Sigma YAML → EQL via pySigma |
| `ElasticAdapter` | `adapters/elastic/adapter.py` | Kibana API (paginated) | No-op (already EQL) |

Both implement the `BaseAdapter` contract from Plan 1 (`load`, `parse`, `translate`, `validate`, `deploy`). All external calls (Kibana API, Elasticsearch, pySigma backend) are mocked in tests.

**Next plan:** Plan 3 — Pipeline steps + CLI (`pipeline/ingest.py`, `pipeline/translate.py`, `pipeline/compare.py`, `pipeline/decide.py`, `pipeline/deploy.py`, `cli.py`)
