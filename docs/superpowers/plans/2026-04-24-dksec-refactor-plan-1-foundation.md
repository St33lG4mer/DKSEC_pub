# DKSec Refactor — Plan 1: Foundation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the shared foundation that all other refactor plans depend on: canonical `RuleAST` data model, config loader, ECS normalizer, scoring, Streamlit theme, input source helpers, file storage layer, and the `BaseAdapter` ABC.

**Architecture:** Extract logic from `utils.py` into focused single-responsibility modules under `core/` and `storage/`. Define the `BaseAdapter` contract in `adapters/base.py`. No existing files are deleted in this plan — old code stays in place until Plan 6 (Migration + Cleanup). New code is tested independently. The old `utils.py` and all existing pages continue to work unchanged throughout this plan.

**Tech Stack:** Python 3.10+, `dataclasses`, `pathlib`, `PyYAML`, `requests`, `gitpython` (for GitSource), `pytest`

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `core/__init__.py` | Create | Package marker |
| `core/ast_model.py` | Create | `RuleAST`, `Condition`, `ValidationResult` dataclasses |
| `core/config.py` | Create | Load `config.yaml` without Streamlit dependency |
| `core/normalizer.py` | Create | ECS token extraction, Jaccard similarity, MITRE tag normalization |
| `core/scoring.py` | Create | Rule scoring algorithm |
| `core/theme.py` | Create | Streamlit CSS constants + `apply_theme()` |
| `core/sources/__init__.py` | Create | Package marker |
| `core/sources/folder_source.py` | Create | Walk a local directory, yield file paths |
| `core/sources/git_source.py` | Create | Clone/pull a git repo, return local path |
| `core/sources/api_source.py` | Create | Paginate a REST API, yield raw dicts |
| `storage/__init__.py` | Create | Package marker |
| `storage/rule_store.py` | Create | Read/write `RuleAST` JSON files under `catalogs/` |
| `storage/result_store.py` | Create | Read/write overlap, unique, alert, report JSON under `output/` |
| `adapters/__init__.py` | Create | Package marker |
| `adapters/base.py` | Create | `BaseAdapter` ABC |
| `tests/__init__.py` | Create | Package marker |
| `tests/core/__init__.py` | Create | Package marker |
| `tests/core/test_ast_model.py` | Create | Tests for RuleAST serialization/deserialization |
| `tests/core/test_normalizer.py` | Create | Tests for token extraction and Jaccard |
| `tests/core/test_scoring.py` | Create | Tests for scoring algorithm |
| `tests/core/test_config.py` | Create | Tests for config loader |
| `tests/core/sources/__init__.py` | Create | Package marker |
| `tests/core/sources/test_folder_source.py` | Create | Tests for FolderSource |
| `tests/storage/__init__.py` | Create | Package marker |
| `tests/storage/test_rule_store.py` | Create | Tests for RuleStore read/write |
| `tests/storage/test_result_store.py` | Create | Tests for ResultStore read/write |
| `tests/adapters/__init__.py` | Create | Package marker |
| `tests/adapters/test_base_adapter.py` | Create | Tests that BaseAdapter enforces abstract methods |
| `requirements.txt` | Modify | Add `gitpython` |

---

## Task 1: Project scaffold & `core/ast_model.py`

**Files:**
- Create: `core/__init__.py`
- Create: `core/ast_model.py`
- Create: `tests/__init__.py`
- Create: `tests/core/__init__.py`
- Create: `tests/core/test_ast_model.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/core/test_ast_model.py
import json
from core.ast_model import Condition, RuleAST, ValidationResult


def _sample_rule() -> RuleAST:
    return RuleAST(
        id="abc123",
        catalog="sigma",
        name="Test Rule",
        description="A test rule",
        severity="high",
        mitre_techniques=["attack.t1059.001"],
        event_categories=["process"],
        conditions=[
            Condition(
                field="process.name",
                raw_field="Image",
                operator="==",
                values=["cmd.exe"],
                raw_values=["cmd.exe"],
            )
        ],
        raw_query="process where process.name == \"cmd.exe\"",
        language="eql",
        translated_query=None,
        source_path="/rules/test.yml",
        metadata={"author": "test"},
    )


def test_rule_ast_roundtrip():
    rule = _sample_rule()
    data = rule.to_dict()
    restored = RuleAST.from_dict(data)
    assert restored.id == rule.id
    assert restored.catalog == rule.catalog
    assert restored.name == rule.name
    assert restored.severity == rule.severity
    assert restored.mitre_techniques == rule.mitre_techniques
    assert restored.event_categories == rule.event_categories
    assert len(restored.conditions) == 1
    assert restored.conditions[0].field == "process.name"
    assert restored.conditions[0].values == ["cmd.exe"]
    assert restored.translated_query is None
    assert restored.metadata == {"author": "test"}


def test_rule_ast_to_json_string():
    rule = _sample_rule()
    s = rule.to_json()
    data = json.loads(s)
    assert data["id"] == "abc123"
    assert data["catalog"] == "sigma"


def test_rule_ast_from_json_string():
    rule = _sample_rule()
    restored = RuleAST.from_json(rule.to_json())
    assert restored.id == rule.id


def test_validation_result_valid():
    v = ValidationResult(valid=True)
    assert v.valid is True
    assert v.error is None


def test_validation_result_invalid():
    v = ValidationResult(valid=False, error="unknown field [process.bad]")
    assert v.valid is False
    assert "unknown field" in v.error


def test_condition_fields():
    c = Condition(
        field="process.name",
        raw_field="Image",
        operator="like~",
        values=["powershell*"],
        raw_values=["*powershell*"],
    )
    assert c.field == "process.name"
    assert c.operator == "like~"
```

- [ ] **Step 2: Run tests to confirm they fail**

```
pytest tests/core/test_ast_model.py -v
```

Expected: `ModuleNotFoundError: No module named 'core'`

- [ ] **Step 3: Create package markers**

```python
# core/__init__.py
# (empty)
```

```python
# tests/__init__.py
# (empty)
```

```python
# tests/core/__init__.py
# (empty)
```

- [ ] **Step 4: Implement `core/ast_model.py`**

```python
# core/ast_model.py
"""Canonical rule data model shared across all catalog adapters."""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field


@dataclass
class Condition:
    """A single normalized condition within a rule."""
    field: str          # ECS-normalized field name, e.g. "process.name"
    raw_field: str      # Original field name from the source catalog
    operator: str       # "==" | "!=" | "like~" | "in" | "wildcard" | ":"
    values: list[str]   # Normalized values
    raw_values: list[str]  # Original values

    def to_dict(self) -> dict:
        return {
            "field": self.field,
            "raw_field": self.raw_field,
            "operator": self.operator,
            "values": self.values,
            "raw_values": self.raw_values,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Condition":
        return cls(
            field=d["field"],
            raw_field=d.get("raw_field", d["field"]),
            operator=d["operator"],
            values=d["values"],
            raw_values=d.get("raw_values", d["values"]),
        )


@dataclass
class RuleAST:
    """
    Canonical representation of a detection rule, catalog-agnostic.
    All adapters normalize their source format into this structure.
    """
    id: str                        # Stable UUID (generated on first parse)
    catalog: str                   # "sigma" | "elastic" | "splunk" | ...
    name: str
    description: str
    severity: str                  # "critical" | "high" | "medium" | "low"
    mitre_techniques: list[str]    # e.g. ["attack.t1059.001"]
    event_categories: list[str]    # e.g. ["process", "network"]
    conditions: list[Condition]
    raw_query: str                 # Original query string, unchanged
    language: str                  # "eql" | "kuery" | "esql" | "sigma" | ...
    translated_query: str | None   # ECS-normalized query set by translate step
    source_path: str               # Original file path or API endpoint
    metadata: dict = field(default_factory=dict)  # Catalog-specific extras

    @classmethod
    def new_id(cls) -> str:
        return str(uuid.uuid4())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "catalog": self.catalog,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "mitre_techniques": self.mitre_techniques,
            "event_categories": self.event_categories,
            "conditions": [c.to_dict() for c in self.conditions],
            "raw_query": self.raw_query,
            "language": self.language,
            "translated_query": self.translated_query,
            "source_path": self.source_path,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RuleAST":
        return cls(
            id=d["id"],
            catalog=d["catalog"],
            name=d["name"],
            description=d.get("description", ""),
            severity=d["severity"],
            mitre_techniques=d.get("mitre_techniques", []),
            event_categories=d.get("event_categories", []),
            conditions=[Condition.from_dict(c) for c in d.get("conditions", [])],
            raw_query=d.get("raw_query", ""),
            language=d.get("language", "eql"),
            translated_query=d.get("translated_query"),
            source_path=d.get("source_path", ""),
            metadata=d.get("metadata", {}),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    @classmethod
    def from_json(cls, s: str) -> "RuleAST":
        return cls.from_dict(json.loads(s))


@dataclass
class ValidationResult:
    """Result of a syntax validation check on a translated query."""
    valid: bool
    error: str | None = None
    category: str | None = None  # e.g. "unknown_field", "type_mismatch", "syntax_error"
```

- [ ] **Step 5: Run tests and verify they pass**

```
pytest tests/core/test_ast_model.py -v
```

Expected: all 6 tests PASS

- [ ] **Step 6: Commit**

```
git add core/__init__.py core/ast_model.py tests/__init__.py tests/core/__init__.py tests/core/test_ast_model.py
git commit -m "feat(core): add canonical RuleAST, Condition, ValidationResult dataclasses"
```

---

## Task 2: `core/config.py`

**Files:**
- Create: `core/config.py`
- Create: `tests/core/test_config.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/core/test_config.py
import os
from pathlib import Path

import pytest
import yaml


def test_load_config_from_file(tmp_path):
    from core.config import load_config

    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        yaml.dump({
            "kibana": {"url": "https://kibana.example.com"},
            "elasticsearch": {"host": "https://es.example.com", "user": "elastic", "password": "secret"},
        }),
        encoding="utf-8",
    )
    config = load_config(cfg_file)
    assert config["kibana"]["url"] == "https://kibana.example.com"
    assert config["elasticsearch"]["user"] == "elastic"


def test_load_config_returns_defaults_when_missing(tmp_path):
    from core.config import load_config

    config = load_config(tmp_path / "nonexistent.yaml")
    assert "kibana" in config
    assert "elasticsearch" in config
    assert config["kibana"]["url"] == ""


def test_load_config_env_override(tmp_path, monkeypatch):
    from core.config import load_config

    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        yaml.dump({"kibana": {"url": "https://original.example.com"}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("DKSEC_KIBANA_URL", "https://override.example.com")
    config = load_config(cfg_file)
    assert config["kibana"]["url"] == "https://override.example.com"


def test_kibana_headers():
    from core.config import kibana_headers

    headers = kibana_headers("elastic", "password123")
    assert "Authorization" in headers
    assert headers["Authorization"].startswith("Basic ")
    assert headers["kbn-xsrf"] == "true"
```

- [ ] **Step 2: Run tests to confirm they fail**

```
pytest tests/core/test_config.py -v
```

Expected: `ModuleNotFoundError: No module named 'core.config'`

- [ ] **Step 3: Implement `core/config.py`**

```python
# core/config.py
"""Config loader — no Streamlit dependency."""
from __future__ import annotations

import base64
import os
from pathlib import Path

import yaml

BASE_DIR = Path(__file__).parent.parent

_DEFAULTS: dict = {
    "kibana": {"url": ""},
    "elasticsearch": {"host": "", "user": "", "password": ""},
    "sigma": {
        "input_dirs": [],
        "output_dir": "catalogs/sigma/raw",
        "failed_log": "catalogs/sigma/failed/failed.log",
        "status_filter": ["stable", "test"],
    },
}


def load_config(path: Path | None = None) -> dict:
    """
    Load configuration in priority order:
    1. Environment variable overrides (DKSEC_KIBANA_URL, etc.)
    2. config.yaml at `path` (defaults to BASE_DIR/config.yaml)
    3. Built-in defaults

    Returns a merged dict — always safe to call even if no config file exists.
    """
    cfg_path = path if path is not None else BASE_DIR / "config.yaml"

    config: dict = {
        "kibana": dict(_DEFAULTS["kibana"]),
        "elasticsearch": dict(_DEFAULTS["elasticsearch"]),
        "sigma": dict(_DEFAULTS["sigma"]),
    }

    if cfg_path.exists():
        try:
            loaded = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
            _deep_merge(config, loaded)
        except Exception:
            pass

    # Environment variable overrides
    if url := os.environ.get("DKSEC_KIBANA_URL"):
        config["kibana"]["url"] = url
    if host := os.environ.get("DKSEC_ES_HOST"):
        config["elasticsearch"]["host"] = host
    if user := os.environ.get("DKSEC_ES_USER"):
        config["elasticsearch"]["user"] = user
    if password := os.environ.get("DKSEC_ES_PASSWORD"):
        config["elasticsearch"]["password"] = password

    return config


def _deep_merge(base: dict, override: dict) -> None:
    """Merge `override` into `base` in-place, recursing into nested dicts."""
    for key, val in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(val, dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val


def kibana_headers(user: str, password: str) -> dict:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {
        "Authorization": f"Basic {token}",
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
    }
```

- [ ] **Step 4: Run tests and verify they pass**

```
pytest tests/core/test_config.py -v
```

Expected: all 4 tests PASS

- [ ] **Step 5: Commit**

```
git add core/config.py tests/core/test_config.py
git commit -m "feat(core): add config loader with env override support"
```

---

## Task 3: `core/normalizer.py`

Extracts `extract_eql_tokens`, `jaccard`, `_normalize_elastic_mitre_tag`, and `_risk_to_severity` from `utils.py` into a pure, Streamlit-free module.

**Files:**
- Create: `core/normalizer.py`
- Create: `tests/core/test_normalizer.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/core/test_normalizer.py
from core.normalizer import (
    extract_eql_tokens,
    get_event_categories,
    jaccard,
    normalize_elastic_mitre_tag,
    risk_to_severity,
)


def test_extract_eql_tokens_fields():
    tokens = extract_eql_tokens('process where process.name == "cmd.exe"')
    assert "process.name" in tokens


def test_extract_eql_tokens_event_category():
    tokens = extract_eql_tokens('process where process.name == "cmd.exe"')
    assert "@cat:process" in tokens


def test_extract_eql_tokens_quoted_value():
    tokens = extract_eql_tokens('process where process.name == "powershell.exe"')
    assert "@val:powershell.exe" in tokens


def test_extract_eql_tokens_stops_short_values():
    tokens = extract_eql_tokens('process where process.name == "ok"')
    # "ok" is shorter than 3 chars in re.search(r"[a-z]{3,}") — not added
    assert not any(t.startswith("@val:ok") for t in tokens)


def test_extract_eql_tokens_empty():
    assert extract_eql_tokens("") == frozenset()


def test_get_event_categories():
    tokens = frozenset(["process.name", "@cat:process", "@val:cmd.exe"])
    cats = get_event_categories(tokens)
    assert cats == frozenset(["@cat:process"])


def test_jaccard_identical():
    a = frozenset(["a", "b", "c"])
    assert jaccard(a, a) == 1.0


def test_jaccard_disjoint():
    a = frozenset(["a", "b"])
    b = frozenset(["c", "d"])
    assert jaccard(a, b) == 0.0


def test_jaccard_partial():
    a = frozenset(["a", "b", "c"])
    b = frozenset(["b", "c", "d"])
    score = jaccard(a, b)
    assert abs(score - 2 / 4) < 1e-9  # intersection=2, union=4


def test_jaccard_both_empty():
    assert jaccard(frozenset(), frozenset()) == 0.0


def test_normalize_elastic_mitre_tag_tactic():
    result = normalize_elastic_mitre_tag("Tactic: Execution")
    assert result == "attack.execution"


def test_normalize_elastic_mitre_tag_technique():
    result = normalize_elastic_mitre_tag("Technique: Command and Scripting Interpreter (T1059)")
    assert result == "attack.t1059"


def test_normalize_elastic_mitre_tag_subtechnique():
    result = normalize_elastic_mitre_tag("Subtechnique: PowerShell (T1059.001)")
    assert result == "attack.t1059.001"


def test_normalize_elastic_mitre_tag_unrecognized():
    assert normalize_elastic_mitre_tag("OS: Windows") is None


def test_risk_to_severity_boundaries():
    assert risk_to_severity(99) == "critical"
    assert risk_to_severity(73) == "high"
    assert risk_to_severity(47) == "medium"
    assert risk_to_severity(21) == "low"
    assert risk_to_severity(0) == "low"
    assert risk_to_severity(100) == "critical"
```

- [ ] **Step 2: Run tests to confirm they fail**

```
pytest tests/core/test_normalizer.py -v
```

Expected: `ModuleNotFoundError: No module named 'core.normalizer'`

- [ ] **Step 3: Implement `core/normalizer.py`**

```python
# core/normalizer.py
"""
ECS field normalization, token extraction, and Jaccard similarity.
Pure Python — no Streamlit, no SIEM dependencies.
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Token extraction regexes (same patterns as original utils.py)
# ---------------------------------------------------------------------------
_ECS_FIELD_RE = re.compile(r"\b([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+)\b")
_EVENT_CAT_RE = re.compile(
    r"\b(process|network|file|registry|driver|library|dns|api|"
    r"authentication|iam|configuration|database|email|"
    r"intrusion_detection|malware|package|session|threat|web)\s+where\b",
    re.I,
)
_QUOTED_RE = re.compile(r'"([^"]{3,})"')
_WILDCARD_ONLY = re.compile(r'^[\*\?\s\\/.\-_]+$')
_STOP_VALS = frozenset({"true", "false", "null", "none", "yes", "no", "and", "or", "not"})


def extract_eql_tokens(query: str) -> frozenset:
    """Extract ECS fields, event categories, and meaningful quoted values from an EQL query."""
    if not query:
        return frozenset()
    tokens: set[str] = set()
    for m in _ECS_FIELD_RE.finditer(query):
        tokens.add(m.group(1).lower())
    for m in _EVENT_CAT_RE.finditer(query):
        tokens.add(f"@cat:{m.group(1).lower()}")
    for m in _QUOTED_RE.finditer(query):
        val = m.group(1).strip().lower()
        if val in _STOP_VALS or _WILDCARD_ONLY.match(val):
            continue
        if re.search(r"[a-z]{3,}", val):
            tokens.add(f"@val:{val[:60]}")
    return frozenset(tokens)


def get_event_categories(tokens: frozenset) -> frozenset:
    """Return only the @cat: prefixed tokens from a token set."""
    return frozenset(t for t in tokens if t.startswith("@cat:"))


def jaccard(a: frozenset, b: frozenset) -> float:
    """Jaccard similarity between two token sets. Returns 0.0 if both empty."""
    if not a and not b:
        return 0.0
    union = len(a | b)
    return len(a & b) / union if union else 0.0


def normalize_elastic_mitre_tag(tag: str) -> str | None:
    """
    Convert an Elastic SIEM MITRE tag to attack.* format.
    Returns None if the tag is not a recognized MITRE tag.

    Examples:
        "Tactic: Execution"                               → "attack.execution"
        "Technique: Command and Scripting (T1059)"        → "attack.t1059"
        "Subtechnique: PowerShell (T1059.001)"            → "attack.t1059.001"
    """
    m = re.match(r"^Tactic:\s*(.+)$", tag, re.I)
    if m:
        return "attack." + m.group(1).strip().lower().replace(" ", "-")
    m = re.match(r"^(?:Technique|Subtechnique):.*\(([Tt]\d+(?:\.\d+)?)\)\s*$", tag)
    if m:
        return "attack." + m.group(1).lower()
    return None


def risk_to_severity(risk: int) -> str:
    """Convert a numeric risk score (0-100) to a severity label."""
    if risk >= 99:
        return "critical"
    if risk >= 73:
        return "high"
    if risk >= 47:
        return "medium"
    return "low"


SEVERITY_TO_RISK: dict[str, int] = {
    "critical": 99,
    "high": 73,
    "medium": 47,
    "low": 21,
    "informational": 21,
}

SEV_COLORS: dict[str, str] = {
    "critical": "#f85149",
    "high": "#d29922",
    "medium": "#58a6ff",
    "low": "#3fb950",
    "?": "#8b949e",
}
```

- [ ] **Step 4: Run tests and verify they pass**

```
pytest tests/core/test_normalizer.py -v
```

Expected: all 15 tests PASS

- [ ] **Step 5: Commit**

```
git add core/normalizer.py tests/core/test_normalizer.py
git commit -m "feat(core): add ECS normalizer, token extraction, Jaccard similarity"
```

---

## Task 4: `core/scoring.py`

**Files:**
- Create: `core/scoring.py`
- Create: `tests/core/test_scoring.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/core/test_scoring.py
from core.ast_model import RuleAST, Condition
from core.scoring import classify_rule, normalize_scores, score_rule


def _make_rule(severity="high", techniques=None, translated_query="process where process.name == \"x\""):
    return RuleAST(
        id="test-1",
        catalog="sigma",
        name="Test",
        description="",
        severity=severity,
        mitre_techniques=techniques or ["attack.t1059"],
        event_categories=["process"],
        conditions=[],
        raw_query=translated_query or "",
        language="eql",
        translated_query=translated_query,
        source_path="",
        metadata={},
    )


def test_score_rule_baseline():
    rule = _make_rule(severity="high", techniques=["attack.t1059"])
    # risk_score for high = 73, +5 for 1 technique, +10 for valid eql = 88
    score = score_rule(rule, has_overlap=False, alert_fires=0)
    assert score == 73 + 10 + 5  # risk + valid_eql + techniques


def test_score_rule_overlap_penalty():
    rule = _make_rule()
    no_overlap = score_rule(rule, has_overlap=False, alert_fires=0)
    with_overlap = score_rule(rule, has_overlap=True, alert_fires=0)
    assert with_overlap == no_overlap - 15


def test_score_rule_alert_bonus_capped():
    rule = _make_rule()
    score_10_fires = score_rule(rule, has_overlap=False, alert_fires=10)
    score_50_fires = score_rule(rule, has_overlap=False, alert_fires=50)
    assert score_10_fires == score_rule(rule, has_overlap=False, alert_fires=0) + 20
    assert score_50_fires == score_10_fires  # capped at +20


def test_score_rule_no_valid_eql():
    rule = _make_rule(translated_query=None)
    score = score_rule(rule, has_overlap=False, alert_fires=0)
    # No +10 for valid_eql
    assert score == 73 + 5  # risk + techniques only


def test_normalize_scores_range():
    rules = [_make_rule("critical"), _make_rule("low"), _make_rule("medium")]
    raw = [score_rule(r, False, 0) for r in rules]
    normalized = normalize_scores(raw)
    assert min(normalized) == 0.0
    assert max(normalized) == 100.0


def test_normalize_scores_single():
    # Single value — all get 50.0 to avoid divide-by-zero
    normalized = normalize_scores([42])
    assert normalized == [50.0]


def test_classify_rule_dead():
    assert classify_rule(alert_fires=0, severity="high") == "dead"


def test_classify_rule_noisy():
    assert classify_rule(alert_fires=60, severity="low") == "noisy"


def test_classify_rule_valuable():
    assert classify_rule(alert_fires=5, severity="critical") == "valuable"


def test_classify_rule_active():
    assert classify_rule(alert_fires=3, severity="medium") == "active"
```

- [ ] **Step 2: Run tests to confirm they fail**

```
pytest tests/core/test_scoring.py -v
```

Expected: `ModuleNotFoundError: No module named 'core.scoring'`

- [ ] **Step 3: Implement `core/scoring.py`**

```python
# core/scoring.py
"""Rule scoring and classification — extracted from utils.py."""
from __future__ import annotations

from core.ast_model import RuleAST
from core.normalizer import SEVERITY_TO_RISK


def score_rule(
    rule: RuleAST,
    has_overlap: bool,
    alert_fires: int,
) -> int:
    """
    Compute a raw composite score for a rule.

    Formula (same as original utils.py):
        risk_score
        + 10  if translated_query is not None (valid EQL)
        + 5   × number of MITRE techniques
        - 15  if has_overlap (duplicate coverage)
        + min(alert_fires × 2, 20)  (capped alert bonus)
    """
    risk = SEVERITY_TO_RISK.get(rule.severity, 47)
    valid_eql_bonus = 10 if rule.translated_query is not None else 0
    technique_bonus = 5 * len(rule.mitre_techniques)
    overlap_penalty = -15 if has_overlap else 0
    alert_bonus = min(alert_fires * 2, 20)
    return risk + valid_eql_bonus + technique_bonus + overlap_penalty + alert_bonus


def normalize_scores(raw_scores: list[int]) -> list[float]:
    """
    Min-max normalize a list of raw scores to the range [0, 100].
    If all scores are identical, returns 50.0 for each to avoid divide-by-zero.
    """
    if not raw_scores:
        return []
    mn = min(raw_scores)
    mx = max(raw_scores)
    if mx == mn:
        return [50.0] * len(raw_scores)
    return [(s - mn) / (mx - mn) * 100 for s in raw_scores]


def classify_rule(alert_fires: int, severity: str) -> str:
    """
    Classify a rule into one of four operational categories.

    dead     — never fired in 24h
    noisy    — 50+ fires, low or medium severity (likely false positive)
    valuable — any fires, high or critical severity
    active   — fired but doesn't meet noisy or valuable criteria
    """
    if alert_fires == 0:
        return "dead"
    if alert_fires >= 50 and severity in ("low", "medium"):
        return "noisy"
    if severity in ("high", "critical"):
        return "valuable"
    return "active"
```

- [ ] **Step 4: Run tests and verify they pass**

```
pytest tests/core/test_scoring.py -v
```

Expected: all 10 tests PASS

- [ ] **Step 5: Commit**

```
git add core/scoring.py tests/core/test_scoring.py
git commit -m "feat(core): add rule scoring and classification"
```

---

## Task 5: `core/theme.py`

**Files:**
- Create: `core/theme.py`

No tests needed — this is pure CSS constants. Validated visually when the UI is refactored in Plan 5.

- [ ] **Step 1: Create `core/theme.py`**

```python
# core/theme.py
"""Streamlit GitHub Dark theme — CSS constants and helpers."""
from __future__ import annotations

import math

THEME_CSS = """
<style>
[data-testid="stAppViewContainer"],
[data-testid="stMain"] {
    background-color: #0d1117;
    color: #e6edf3;
}
[data-testid="stSidebar"] {
    background-color: #0d1117 !important;
    border-right: 1px solid #30363d;
}
header[data-testid="stHeader"] {
    background-color: #0d1117;
    border-bottom: 1px solid #21262d;
}
.metric-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    margin-bottom: 0;
}
.metric-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 20px 22px 16px;
    text-align: center;
    height: 100%;
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    transition: border-color 0.2s;
}
.metric-card:hover { border-color: #58a6ff; }
.metric-card .mc-label {
    font-size: 0.70rem;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.10em;
    margin-bottom: 8px;
}
.metric-card .mc-value {
    font-size: 2.4rem;
    font-weight: 700;
    line-height: 1.1;
}
.metric-card .mc-sub {
    font-size: 0.78rem;
    color: #8b949e;
    margin-top: 6px;
    min-height: 16px;
}
.section-header {
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: #8b949e;
    padding-bottom: 6px;
    border-bottom: 1px solid #21262d;
    margin: 24px 0 14px;
}
.coverage-pill {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 600;
    margin: 3px 3px;
}
.pill-sigma   { background: #0d2a4a; color: #58a6ff; border: 1px solid #1a4a8a; }
.pill-elastic { background: #3d2a00; color: #d29922; border: 1px solid #6b4a00; }
.pill-both    { background: #0d3a1a; color: #3fb950; border: 1px solid #1a6b30; }
[data-testid="stDataFrame"] { border: 1px solid #30363d; border-radius: 8px; }
[data-testid="stSidebarNav"] a { color: #8b949e !important; font-size: 0.85rem; }
[data-testid="stSidebarNav"] a:hover,
[data-testid="stSidebarNav"] a[aria-selected="true"] {
    color: #e6edf3 !important;
    background: #21262d !important;
}
.status-badge { display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:20px;font-size:0.75rem;font-weight:600; }
.status-disconnected { background:#2d1a1a;color:#f85149;border:1px solid #5a1a1a; }
.status-connected    { background:#0d2a1a;color:#3fb950;border:1px solid #1a5a30; }
.metric-card-muted { background:#0d1117;border:1px solid #21262d;border-radius:10px;padding:20px 22px 16px;text-align:center;opacity:0.55; }
.metric-card-muted .mc-label { font-size:0.70rem;color:#484f58;text-transform:uppercase;letter-spacing:0.10em;margin-bottom:8px; }
.metric-card-muted .mc-value { font-size:2.4rem;font-weight:700;color:#484f58;line-height:1.1; }
.metric-card-muted .mc-sub   { font-size:0.78rem;color:#30363d;margin-top:6px; }
</style>
"""


def apply_theme() -> None:
    """Inject the GitHub Dark CSS into the current Streamlit page."""
    import streamlit as st
    st.markdown(THEME_CSS, unsafe_allow_html=True)


def metric_card_html(label: str, value: str, sub: str = "", color: str = "#e6edf3") -> str:
    sub_html = f'<div class="mc-sub">{sub}</div>' if sub else '<div class="mc-sub"></div>'
    return (
        f'<div class="metric-card">'
        f'<div class="mc-label">{label}</div>'
        f'<div class="mc-value" style="color:{color}">{value}</div>'
        f'{sub_html}'
        f'</div>'
    )


def metric_card_muted_html(label: str, value: str, sub: str = "") -> str:
    sub_html = f'<div class="mc-sub">{sub}</div>' if sub else '<div class="mc-sub"></div>'
    return (
        f'<div class="metric-card-muted">'
        f'<div class="mc-label">{label}</div>'
        f'<div class="mc-value">{value}</div>'
        f'{sub_html}'
        f'</div>'
    )


def alert_donut_html(total: int, by_severity: dict) -> str:
    """SVG donut chart inside a metric-card div."""
    from core.normalizer import SEV_COLORS
    sev_order = ["critical", "high", "medium", "low"]
    r, cx, cy, sw = 36, 55, 55, 16
    C = 2 * math.pi * r
    total_v = sum(by_severity.get(s, 0) for s in sev_order) or 1

    arcs, cum = [], 0.0
    for sev in sev_order:
        v = by_severity.get(sev, 0)
        if not v:
            continue
        dash = C * v / total_v
        arcs.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none"'
            f' stroke="{SEV_COLORS[sev]}" stroke-width="{sw}"'
            f' stroke-dasharray="{dash:.1f} {C - dash:.1f}"'
            f' stroke-dashoffset="{C / 4 - cum:.1f}" />'
        )
        cum += dash

    total_str = f"{total:,}" if total > 0 else "—"
    bg = f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#21262d" stroke-width="{sw}" />'
    svg = (
        f'<svg width="110" height="110" viewBox="0 0 110 110">'
        f'{bg}{"".join(arcs)}'
        f'<text x="{cx}" y="{cy - 5}" text-anchor="middle" dominant-baseline="central"'
        f' font-size="20" font-weight="700" fill="#e6edf3">{total_str}</text>'
        f'<text x="{cx}" y="{cy + 14}" text-anchor="middle"'
        f' font-size="9" fill="#8b949e">24h alerts</text>'
        f'</svg>'
    )
    return (
        '<div class="metric-card" style="display:flex;flex-direction:column;'
        'align-items:center;justify-content:space-around">'
        '<div class="mc-label">TOTAL 24H ALERTS</div>'
        f'{svg}'
        '</div>'
    )
```

- [ ] **Step 2: Commit**

```
git add core/theme.py
git commit -m "feat(core): add Streamlit GitHub Dark theme module"
```

---

## Task 6: `core/sources/` — input source helpers

**Files:**
- Create: `core/sources/__init__.py`
- Create: `core/sources/folder_source.py`
- Create: `core/sources/git_source.py`
- Create: `core/sources/api_source.py`
- Create: `tests/core/sources/__init__.py`
- Create: `tests/core/sources/test_folder_source.py`
- Modify: `requirements.txt` — add `gitpython>=3.1`

- [ ] **Step 1: Write failing tests for FolderSource**

```python
# tests/core/sources/test_folder_source.py
from pathlib import Path

import pytest

from core.sources.folder_source import FolderSource


def test_folder_source_finds_files(tmp_path):
    (tmp_path / "rule1.yml").write_text("title: Rule 1\n", encoding="utf-8")
    (tmp_path / "rule2.yml").write_text("title: Rule 2\n", encoding="utf-8")
    (tmp_path / "readme.txt").write_text("ignore me\n", encoding="utf-8")

    source = FolderSource(path=tmp_path, glob_pattern="*.yml")
    paths = list(source.iter_paths())

    assert len(paths) == 2
    assert all(p.suffix == ".yml" for p in paths)


def test_folder_source_recursive(tmp_path):
    subdir = tmp_path / "sub"
    subdir.mkdir()
    (tmp_path / "a.yml").write_text("", encoding="utf-8")
    (subdir / "b.yml").write_text("", encoding="utf-8")

    source = FolderSource(path=tmp_path, glob_pattern="**/*.yml")
    paths = list(source.iter_paths())
    assert len(paths) == 2


def test_folder_source_missing_path_raises(tmp_path):
    source = FolderSource(path=tmp_path / "nonexistent", glob_pattern="*.yml")
    with pytest.raises(FileNotFoundError):
        list(source.iter_paths())


def test_folder_source_iter_contents(tmp_path):
    (tmp_path / "rule.yml").write_text("title: Test\n", encoding="utf-8")
    source = FolderSource(path=tmp_path, glob_pattern="*.yml")
    items = list(source.iter_contents())
    assert len(items) == 1
    path, content = items[0]
    assert "title: Test" in content
```

- [ ] **Step 2: Run tests to confirm they fail**

```
pytest tests/core/sources/test_folder_source.py -v
```

Expected: `ModuleNotFoundError: No module named 'core.sources'`

- [ ] **Step 3: Create `core/sources/__init__.py` and `core/sources/folder_source.py`**

```python
# core/sources/__init__.py
# (empty)
```

```python
# tests/core/sources/__init__.py
# (empty)
```

```python
# core/sources/folder_source.py
"""Walk a local directory and yield file paths or their text content."""
from __future__ import annotations

from pathlib import Path


class FolderSource:
    """Yield file paths from a local directory matching a glob pattern."""

    def __init__(self, path: Path, glob_pattern: str = "**/*.yml") -> None:
        self.path = Path(path)
        self.glob_pattern = glob_pattern

    def iter_paths(self):
        """Yield Path objects for each matching file. Raises FileNotFoundError if dir missing."""
        if not self.path.exists():
            raise FileNotFoundError(f"Source directory not found: {self.path}")
        yield from sorted(self.path.glob(self.glob_pattern))

    def iter_contents(self):
        """Yield (Path, str) tuples of matching files and their UTF-8 text content."""
        for p in self.iter_paths():
            try:
                yield p, p.read_text(encoding="utf-8")
            except Exception:
                continue
```

- [ ] **Step 4: Run tests and verify they pass**

```
pytest tests/core/sources/test_folder_source.py -v
```

Expected: all 4 tests PASS

- [ ] **Step 5: Create `core/sources/git_source.py`**

```python
# core/sources/git_source.py
"""Clone or pull a git repository and return the local path."""
from __future__ import annotations

from pathlib import Path


class GitSource:
    """
    Clone a git repository to a local path, or pull if it already exists.
    Returns the local path so a FolderSource can walk it.
    """

    def __init__(self, url: str, local_path: Path, ref: str = "HEAD") -> None:
        self.url = url
        self.local_path = Path(local_path)
        self.ref = ref

    def sync(self) -> Path:
        """
        Clone the repo if not present, otherwise pull latest.
        Returns self.local_path after sync.
        Raises RuntimeError on git failure.
        """
        try:
            import git
        except ImportError as e:
            raise ImportError("gitpython is required for GitSource. Run: pip install gitpython") from e

        if self.local_path.exists() and (self.local_path / ".git").exists():
            try:
                repo = git.Repo(self.local_path)
                origin = repo.remotes.origin
                origin.pull()
            except Exception as exc:
                raise RuntimeError(f"Failed to pull {self.url}: {exc}") from exc
        else:
            self.local_path.mkdir(parents=True, exist_ok=True)
            try:
                git.Repo.clone_from(self.url, self.local_path)
            except Exception as exc:
                raise RuntimeError(f"Failed to clone {self.url}: {exc}") from exc

        return self.local_path
```

- [ ] **Step 6: Create `core/sources/api_source.py`**

```python
# core/sources/api_source.py
"""Paginate a REST API and yield raw rule dicts."""
from __future__ import annotations

import time
from typing import Iterator

import requests


class ApiSource:
    """
    Paginate a REST API endpoint that returns a JSON list of rules.
    Handles rate limiting (429) with exponential backoff.
    """

    def __init__(
        self,
        base_url: str,
        headers: dict,
        page_param: str = "page",
        per_page_param: str = "per_page",
        per_page: int = 500,
        data_key: str = "data",
        total_key: str = "total",
        timeout: int = 30,
        max_retries: int = 5,
    ) -> None:
        self.base_url = base_url
        self.headers = headers
        self.page_param = page_param
        self.per_page_param = per_page_param
        self.per_page = per_page
        self.data_key = data_key
        self.total_key = total_key
        self.timeout = timeout
        self.max_retries = max_retries

    def iter_rules(self) -> Iterator[dict]:
        """Yield raw rule dicts from the API, paginating until exhausted."""
        page = 1
        fetched = 0
        total = None

        while True:
            params = {self.page_param: page, self.per_page_param: self.per_page}
            resp = self._get_with_retry(params)
            data = resp.json()
            batch = data.get(self.data_key, [])
            if total is None:
                total = data.get(self.total_key, 0)

            yield from batch
            fetched += len(batch)

            if not batch or fetched >= total:
                break
            page += 1

    def _get_with_retry(self, params: dict) -> requests.Response:
        for attempt in range(self.max_retries):
            resp = requests.get(
                self.base_url,
                headers=self.headers,
                params=params,
                timeout=self.timeout,
            )
            if resp.status_code in (429, 500, 502, 503):
                time.sleep(2 ** attempt)
                continue
            if resp.status_code != 200:
                raise RuntimeError(f"API error {resp.status_code}: {resp.text[:200]}")
            return resp
        raise RuntimeError(f"API request failed after {self.max_retries} retries")
```

- [ ] **Step 7: Add `gitpython` to requirements.txt**

Open `requirements.txt` and add:
```
gitpython>=3.1
```

- [ ] **Step 8: Run all source tests**

```
pytest tests/core/sources/ -v
```

Expected: all 4 FolderSource tests PASS (GitSource and ApiSource have no unit tests — they interact with external services; tested in integration)

- [ ] **Step 9: Commit**

```
git add core/sources/ tests/core/sources/ requirements.txt
git commit -m "feat(core): add FolderSource, GitSource, ApiSource input helpers"
```

---

## Task 7: `storage/rule_store.py` and `storage/result_store.py`

**Files:**
- Create: `storage/__init__.py`
- Create: `storage/rule_store.py`
- Create: `storage/result_store.py`
- Create: `tests/storage/__init__.py`
- Create: `tests/storage/test_rule_store.py`
- Create: `tests/storage/test_result_store.py`

- [ ] **Step 1: Write failing tests for RuleStore**

```python
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
```

- [ ] **Step 2: Write failing tests for ResultStore**

```python
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
```

- [ ] **Step 3: Run tests to confirm they fail**

```
pytest tests/storage/ -v
```

Expected: `ModuleNotFoundError: No module named 'storage'`

- [ ] **Step 4: Implement `storage/rule_store.py`**

```python
# storage/__init__.py
# (empty)
```

```python
# storage/rule_store.py
"""Read and write RuleAST JSON files under catalogs/<catalog>/ast/."""
from __future__ import annotations

from pathlib import Path

from core.ast_model import RuleAST


class RuleStore:
    """
    File-based store for canonical RuleAST objects.
    Layout: <base_dir>/<catalog>/ast/<rule_id>.json
    """

    def __init__(self, base_dir: Path) -> None:
        self.base_dir = Path(base_dir)

    def _ast_dir(self, catalog: str) -> Path:
        d = self.base_dir / catalog / "ast"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def save(self, rule: RuleAST) -> Path:
        """Write a RuleAST to disk. Returns the file path written."""
        path = self._ast_dir(rule.catalog) / f"{rule.id}.json"
        path.write_text(rule.to_json(), encoding="utf-8")
        return path

    def load(self, rule_id: str, catalog: str) -> RuleAST:
        """Load a single RuleAST by id and catalog. Raises FileNotFoundError if missing."""
        path = self.base_dir / catalog / "ast" / f"{rule_id}.json"
        if not path.exists():
            raise FileNotFoundError(f"Rule not found: {path}")
        return RuleAST.from_json(path.read_text(encoding="utf-8"))

    def load_all(self, catalog: str) -> list[RuleAST]:
        """Load all RuleAST files for a given catalog. Returns empty list if none exist."""
        ast_dir = self.base_dir / catalog / "ast"
        if not ast_dir.exists():
            return []
        rules = []
        for path in sorted(ast_dir.glob("*.json")):
            try:
                rules.append(RuleAST.from_json(path.read_text(encoding="utf-8")))
            except Exception:
                continue
        return rules

    def list_catalogs(self) -> list[str]:
        """Return catalog names that have an ast/ subdirectory with at least one file."""
        if not self.base_dir.exists():
            return []
        return [
            d.name for d in sorted(self.base_dir.iterdir())
            if d.is_dir() and (d / "ast").exists() and any((d / "ast").glob("*.json"))
        ]
```

- [ ] **Step 5: Implement `storage/result_store.py`**

```python
# storage/result_store.py
"""Read and write comparison results, decisions, and alerts under output/."""
from __future__ import annotations

import json
from pathlib import Path


class ResultStore:
    """
    File-based store for pipeline output artifacts.
    Layout:
        <base_dir>/overlaps/<a>_vs_<b>.json
        <base_dir>/unique/<a>_vs_<b>.json
        <base_dir>/reports/<a>_vs_<b>_decisions.json
        <base_dir>/alerts/<run_id>.json
    """

    def __init__(self, base_dir: Path) -> None:
        self.base_dir = Path(base_dir)

    def _pair_key(self, a: str, b: str) -> str:
        return f"{a}_vs_{b}"

    def _write(self, subdir: str, filename: str, data: object) -> Path:
        d = self.base_dir / subdir
        d.mkdir(parents=True, exist_ok=True)
        path = d / filename
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def _read(self, subdir: str, filename: str) -> object:
        path = self.base_dir / subdir / filename
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def save_overlaps(self, a: str, b: str, overlaps: list[dict]) -> Path:
        return self._write("overlaps", f"{self._pair_key(a, b)}.json", overlaps)

    def load_overlaps(self, a: str, b: str) -> list[dict]:
        return self._read("overlaps", f"{self._pair_key(a, b)}.json") or []

    def save_unique(self, a: str, b: str, unique: list[dict]) -> Path:
        return self._write("unique", f"{self._pair_key(a, b)}.json", unique)

    def load_unique(self, a: str, b: str) -> list[dict]:
        return self._read("unique", f"{self._pair_key(a, b)}.json") or []

    def save_decisions(self, a: str, b: str, decisions: dict[str, str]) -> Path:
        return self._write("reports", f"{self._pair_key(a, b)}_decisions.json", decisions)

    def load_decisions(self, a: str, b: str) -> dict[str, str]:
        return self._read("reports", f"{self._pair_key(a, b)}_decisions.json") or {}

    def save_alerts(self, run_id: str, alerts: list[dict]) -> Path:
        return self._write("alerts", f"{run_id}.json", alerts)

    def load_alerts(self, run_id: str) -> list[dict]:
        return self._read("alerts", f"{run_id}.json") or []

    def list_alert_runs(self) -> list[str]:
        alerts_dir = self.base_dir / "alerts"
        if not alerts_dir.exists():
            return []
        return [p.stem for p in sorted(alerts_dir.glob("*.json"))]
```

- [ ] **Step 6: Create storage package marker**

```python
# tests/storage/__init__.py
# (empty)
```

- [ ] **Step 7: Run tests and verify they pass**

```
pytest tests/storage/ -v
```

Expected: all 8 tests PASS

- [ ] **Step 8: Commit**

```
git add storage/ tests/storage/
git commit -m "feat(storage): add RuleStore and ResultStore file-based storage layer"
```

---

## Task 8: `adapters/base.py` — BaseAdapter ABC

**Files:**
- Create: `adapters/__init__.py`
- Create: `adapters/base.py`
- Create: `tests/adapters/__init__.py`
- Create: `tests/adapters/test_base_adapter.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/adapters/test_base_adapter.py
import pytest
from core.ast_model import RuleAST, ValidationResult
from adapters.base import BaseAdapter


class ConcreteAdapter(BaseAdapter):
    name = "test"
    source_type = "folder"

    def load(self) -> list[dict]:
        return [{"title": "Rule A", "id": "a1"}]

    def parse(self, raw: dict) -> RuleAST:
        return RuleAST(
            id=raw["id"],
            catalog=self.name,
            name=raw["title"],
            description="",
            severity="medium",
            mitre_techniques=[],
            event_categories=[],
            conditions=[],
            raw_query="",
            language="eql",
            translated_query=None,
            source_path="",
        )

    def translate(self, ast: RuleAST) -> RuleAST:
        ast.translated_query = ast.raw_query
        return ast


class IncompleteAdapter(BaseAdapter):
    name = "incomplete"
    source_type = "folder"
    # Missing: load, parse, translate


def test_concrete_adapter_load():
    adapter = ConcreteAdapter()
    raw = adapter.load()
    assert len(raw) == 1
    assert raw[0]["title"] == "Rule A"


def test_concrete_adapter_parse():
    adapter = ConcreteAdapter()
    raw = {"title": "Rule A", "id": "a1"}
    rule = adapter.parse(raw)
    assert isinstance(rule, RuleAST)
    assert rule.name == "Rule A"
    assert rule.catalog == "test"


def test_concrete_adapter_translate():
    adapter = ConcreteAdapter()
    raw = {"title": "Rule A", "id": "a1"}
    rule = adapter.parse(raw)
    translated = adapter.translate(rule)
    assert translated.translated_query == rule.raw_query


def test_validate_default_returns_valid():
    adapter = ConcreteAdapter()
    raw = {"title": "Rule A", "id": "a1"}
    rule = adapter.parse(raw)
    result = adapter.validate(rule)
    assert isinstance(result, ValidationResult)
    assert result.valid is True


def test_deploy_raises_not_implemented():
    adapter = ConcreteAdapter()
    raw = {"title": "Rule A", "id": "a1"}
    rule = adapter.parse(raw)
    with pytest.raises(NotImplementedError):
        adapter.deploy(rule, client=None)


def test_incomplete_adapter_cannot_instantiate():
    with pytest.raises(TypeError):
        IncompleteAdapter()
```

- [ ] **Step 2: Run tests to confirm they fail**

```
pytest tests/adapters/test_base_adapter.py -v
```

Expected: `ModuleNotFoundError: No module named 'adapters'`

- [ ] **Step 3: Implement `adapters/base.py`**

```python
# adapters/__init__.py
# (empty)
```

```python
# tests/adapters/__init__.py
# (empty)
```

```python
# adapters/base.py
"""Abstract base class for all catalog adapters."""
from __future__ import annotations

from abc import ABC, abstractmethod

from core.ast_model import RuleAST, ValidationResult


class BaseAdapter(ABC):
    """
    Contract that every catalog adapter must implement.
    A catalog adapter knows how to:
      1. load()      — fetch raw rules from a source (git/folder/API)
      2. parse()     — convert one raw rule dict to a canonical RuleAST
      3. translate() — normalize the rule's query/fields to ECS
      4. validate()  — syntax-check the translated query (optional)
      5. deploy()    — push a rule to a SIEM (optional)

    New catalog support = new folder under adapters/ with one adapter.py
    implementing this interface. No other files need to change.
    """

    name: str          # Catalog identifier, e.g. "sigma", "elastic"
    source_type: str   # "git" | "folder" | "api"

    @abstractmethod
    def load(self) -> list[dict]:
        """
        Fetch raw rules from the configured source.
        Returns a list of raw rule dicts (catalog-specific format).
        """

    @abstractmethod
    def parse(self, raw: dict) -> RuleAST:
        """
        Convert a single raw rule dict to a canonical RuleAST.
        The returned RuleAST.translated_query should be None at this stage.
        """

    @abstractmethod
    def translate(self, ast: RuleAST) -> RuleAST:
        """
        Normalize the rule's query and field names to ECS.
        Sets ast.translated_query. Returns the updated ast.
        """

    def validate(self, ast: RuleAST) -> ValidationResult:
        """
        Syntax-check the translated query against the target SIEM.
        Default implementation: always valid (no-op).
        Override in adapters that support live validation (e.g. ElasticAdapter).
        """
        return ValidationResult(valid=True)

    def deploy(self, ast: RuleAST, client) -> bool:
        """
        Push a rule to a SIEM. Returns True on success.
        Default: raises NotImplementedError.
        Override in adapters that support deployment.
        """
        raise NotImplementedError(f"{self.__class__.__name__} does not support deploy()")
```

- [ ] **Step 4: Run tests and verify they pass**

```
pytest tests/adapters/test_base_adapter.py -v
```

Expected: all 6 tests PASS

- [ ] **Step 5: Run the full test suite to ensure nothing is broken**

```
pytest tests/ -v
```

Expected: all tests PASS (approximately 43 tests across all tasks)

- [ ] **Step 6: Commit**

```
git add adapters/ tests/adapters/
git commit -m "feat(adapters): add BaseAdapter ABC — catalog plugin contract"
```

---

## Task 9: Verify existing app still works

The refactor adds new modules but does NOT yet modify `utils.py` or any `pages/`. Confirm nothing is broken.

- [ ] **Step 1: Install new dependency**

```
pip install gitpython
```

- [ ] **Step 2: Confirm dashboard still starts**

```
python -m streamlit run dashboard.py --server.headless true &
sleep 5
curl -s http://localhost:8501 | grep -c "streamlit"
```

Expected: output is `1` or more (Streamlit HTML is served). Kill the process after.

- [ ] **Step 3: Run full test suite one final time**

```
pytest tests/ -v --tb=short
```

Expected: all tests PASS

- [ ] **Step 4: Final commit**

```
git add .
git commit -m "chore: verify foundation plan complete — existing app unchanged"
```

---

## Self-Review Checklist (completed inline)

- **Spec coverage:** RuleAST ✅, Condition ✅, ValidationResult ✅, config loader ✅, ECS normalizer ✅, Jaccard ✅, scoring ✅, theme ✅, GitSource ✅, FolderSource ✅, ApiSource ✅, RuleStore ✅, ResultStore ✅, BaseAdapter ✅
- **Placeholders:** None — all code blocks are complete and runnable
- **Type consistency:** `RuleAST`, `Condition`, `ValidationResult` defined in Task 1 and used consistently in Tasks 4, 7, 8. `SEVERITY_TO_RISK` defined in Task 3, imported in Task 4. `SEV_COLORS` defined in Task 3, imported in Task 5. All method signatures match across tasks.
- **YAGNI check:** `alert_donut_html` kept in theme.py because it's used by the existing dashboard.py (prevents breakage during migration). All other new code is needed by Plans 2–6.
