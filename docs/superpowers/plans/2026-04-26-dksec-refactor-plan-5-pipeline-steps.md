# DKSec Refactor — Plan 5: Pipeline Orchestration Steps

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the three remaining pipeline orchestration steps — `pipeline/ingest.py`, `pipeline/translate.py`, and `pipeline/deploy.py` — that wire adapters to storage and make the end-to-end pipeline runnable. Also extend `storage/rule_store.py` with `save_raw`/`load_raw` to support the two-stage ingest→translate flow.

**Architecture:** Each pipeline step is a thin orchestration layer: it calls an adapter method, handles errors gracefully, and persists results to the appropriate store. No step has external dependencies (network, SIEM) in tests — everything is mocked. This follows the same pattern as Plan 4's `run_attack_chain()`.

| Step | Input | Calls | Output |
|------|-------|-------|--------|
| `ingest_catalog(adapter, store)` | Adapter + RuleStore | `adapter.load()` | Raw dicts saved to `catalogs/<name>/raw/` |
| `translate_catalog(adapter, store)` | Adapter + RuleStore | `adapter.parse()` + `adapter.translate()` + `store.save()` | RuleAST JSON saved to `catalogs/<name>/ast/` |
| `deploy_rules(adapter, rules, client, mode)` | Adapter + rules + SIEM client | `adapter.deploy()` | Rules pushed to SIEM; tagged `dksec-test` (test mode) or permanent |

**Tech Stack:** Python 3.10+, `pytest`, `unittest.mock`, `storage.rule_store.RuleStore`, `adapters.base.BaseAdapter`, `core.ast_model.RuleAST`

---

## Pre-requisite

```
git checkout main
git pull
git checkout -b plan5-pipeline
```

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `storage/rule_store.py` | Extend | Add `save_raw(catalog, raws)` / `load_raw(catalog)` |
| `pipeline/ingest.py` | Create | `IngestResult` + `ingest_catalog(adapter, store)` |
| `pipeline/translate.py` | Create | `TranslateResult` + `translate_catalog(adapter, store)` |
| `pipeline/deploy.py` | Create | `DeployResult` + `deploy_rules(adapter, rules, client, mode)` |
| `tests/storage/test_rule_store.py` | Extend | Add 3 tests for `save_raw`/`load_raw` |
| `tests/pipeline/test_ingest.py` | Create | 5 tests for `ingest_catalog` |
| `tests/pipeline/test_translate.py` | Create | 5 tests for `translate_catalog` |
| `tests/pipeline/test_deploy.py` | Create | 5 tests for `deploy_rules` |
| `tests/pipeline/test_pipeline_integration.py` | Create | 3 end-to-end tests |

---

## Shared helpers (used across test files — reproduce in full per file)

```python
import uuid
from core.ast_model import RuleAST

def _make_raw(rule_id: str | None = None) -> dict:
    """Minimal raw rule dict as returned by adapter.load()."""
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
```

---

## Task 1: Extend `RuleStore` + create `pipeline/ingest.py`

**Files:**
- Extend: `storage/rule_store.py`
- Create: `pipeline/ingest.py`
- Extend: `tests/storage/test_rule_store.py` (append 3 new tests)
- Create: `tests/pipeline/test_ingest.py`

### Step 1: Extend `storage/rule_store.py`

Append two methods to the `RuleStore` class:

```python
    # --- raw rule storage (pre-parse, pre-translate) ---

    def _raw_dir(self, catalog: str) -> Path:
        d = self.base_dir / catalog / "raw"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def save_raw(self, catalog: str, raws: list[dict]) -> Path:
        """
        Persist raw rule dicts (as returned by adapter.load()) to
        <base_dir>/<catalog>/raw/rules.json.
        Overwrites any existing file for this catalog.
        """
        import json
        path = self._raw_dir(catalog) / "rules.json"
        path.write_text(json.dumps(raws, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def load_raw(self, catalog: str) -> list[dict]:
        """
        Load raw rule dicts from <base_dir>/<catalog>/raw/rules.json.
        Returns empty list if the file does not exist.
        """
        import json
        path = self.base_dir / catalog / "raw" / "rules.json"
        if not path.exists():
            return []
        return json.loads(path.read_text(encoding="utf-8"))
```

### Step 2: Append 3 tests to `tests/storage/test_rule_store.py`

```python
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
```

### Step 3: Write the failing tests for `pipeline/ingest.py`

```python
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
```

### Step 4: Create `pipeline/ingest.py`

```python
# pipeline/ingest.py
"""
Step 1 of the DKSec pipeline: load raw rules from a source via an adapter
and persist them for the translate step.

Usage:
    from adapters.sigma.adapter import SigmaAdapter
    from pipeline.ingest import ingest_catalog
    from storage.rule_store import RuleStore
    from pathlib import Path

    adapter = SigmaAdapter(folder_path="catalogs/sigma/raw")
    store = RuleStore(Path("catalogs"))
    result = ingest_catalog(adapter, store)
    print(f"Ingested {result.raw_count} rules from {result.catalog}")
"""
from __future__ import annotations

from dataclasses import dataclass, field

from adapters.base import BaseAdapter
from storage.rule_store import RuleStore


@dataclass
class IngestResult:
    """Summary of a single catalog ingest run."""
    catalog: str
    raw_count: int
    failed_count: int
    errors: list[str] = field(default_factory=list)


def ingest_catalog(adapter: BaseAdapter, store: RuleStore) -> IngestResult:
    """
    Load raw rules from the adapter's source and persist them.

    Calls adapter.load() to fetch raw rule dicts, then saves them via
    store.save_raw(). If load() raises, returns an IngestResult with the
    error recorded — never propagates exceptions to the caller.

    Args:
        adapter:  A BaseAdapter implementation (Sigma, Elastic, etc.)
        store:    RuleStore pointing at the catalogs/ directory

    Returns:
        IngestResult with raw_count, failed_count, and any errors
    """
    try:
        raws = adapter.load()
    except Exception as exc:  # noqa: BLE001
        return IngestResult(catalog=adapter.name, raw_count=0, failed_count=0, errors=[str(exc)])

    store.save_raw(adapter.name, raws)
    return IngestResult(catalog=adapter.name, raw_count=len(raws), failed_count=0, errors=[])
```

### Step 5: Run all tests — expect 174 + 3 + 5 = 182 passing

```python
import subprocess, sys
r = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-q"], capture_output=True, text=True, cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec")
print(r.stdout, r.stderr)
```

### Step 6: Commit

```
git add storage/rule_store.py pipeline/ingest.py tests/storage/test_rule_store.py tests/pipeline/test_ingest.py
git commit -m "feat: add RuleStore.save_raw/load_raw and pipeline/ingest.py

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Task 2: `pipeline/translate.py`

**Files:**
- Create: `pipeline/translate.py`
- Create: `tests/pipeline/test_translate.py`

### Step 1: Write the failing tests

```python
# tests/pipeline/test_translate.py
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
```

### Step 2: Create `pipeline/translate.py`

```python
# pipeline/translate.py
"""
Step 2 of the DKSec pipeline: parse raw rules into canonical RuleAST and
translate them to ECS-normalized form via the catalog adapter.

Usage:
    from adapters.sigma.adapter import SigmaAdapter
    from pipeline.translate import translate_catalog
    from storage.rule_store import RuleStore
    from pathlib import Path

    adapter = SigmaAdapter(folder_path="catalogs/sigma/raw")
    store = RuleStore(Path("catalogs"))
    result = translate_catalog(adapter, store)
    print(f"Translated {result.translated_count} rules ({result.failed_count} failed)")
"""
from __future__ import annotations

from dataclasses import dataclass, field

from adapters.base import BaseAdapter
from storage.rule_store import RuleStore


@dataclass
class TranslateResult:
    """Summary of a single catalog translate run."""
    catalog: str
    translated_count: int
    failed_count: int
    errors: list[str] = field(default_factory=list)


def translate_catalog(adapter: BaseAdapter, store: RuleStore) -> TranslateResult:
    """
    Parse and translate raw rules for a catalog, persisting the results.

    Reads raw rule dicts from store.load_raw(), calls adapter.parse() then
    adapter.translate() on each, and saves the resulting RuleAST via store.save().
    Per-rule failures are recorded in errors and counted in failed_count —
    translate_catalog never raises.

    Args:
        adapter:  A BaseAdapter implementation
        store:    RuleStore pointing at the catalogs/ directory

    Returns:
        TranslateResult with translated_count, failed_count, and errors
    """
    raws = store.load_raw(adapter.name)
    translated_count = 0
    failed_count = 0
    errors: list[str] = []

    for raw in raws:
        try:
            ast = adapter.parse(raw)
            ast = adapter.translate(ast)
            store.save(ast)
            translated_count += 1
        except Exception as exc:  # noqa: BLE001
            failed_count += 1
            errors.append(str(exc))

    return TranslateResult(
        catalog=adapter.name,
        translated_count=translated_count,
        failed_count=failed_count,
        errors=errors,
    )
```

### Step 3: Run all tests — expect ~187 passing

```python
import subprocess, sys
r = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-q"], capture_output=True, text=True, cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec")
print(r.stdout, r.stderr)
```

### Step 4: Commit

```
git add pipeline/translate.py tests/pipeline/test_translate.py
git commit -m "feat: add pipeline/translate.py

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Task 3: `pipeline/deploy.py`

**Files:**
- Create: `pipeline/deploy.py`
- Create: `tests/pipeline/test_deploy.py`

### Step 1: Write the failing tests

```python
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


def test_deploy_rules_calls_adapter_deploy_for_each(tmp_path):
    adapter = _mock_adapter()
    client = MagicMock()
    rules = [_make_ast("r1"), _make_ast("r2"), _make_ast("r3")]

    result = deploy_rules(adapter, rules, client, mode="test")

    assert adapter.deploy.call_count == 3
    assert result.deployed_count == 3
    assert result.failed_count == 0


def test_deploy_rules_records_failure_and_continues(tmp_path):
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
```

### Step 2: Create `pipeline/deploy.py`

```python
# pipeline/deploy.py
"""
Step 3 / Step 6 of the DKSec pipeline: deploy rules to a SIEM via the adapter.

Two modes:
  - "test":      Deploy candidate rules tagged 'dksec-test' so they co-exist
                 with existing SIEM rules during the attack chain run. The
                 adapter is responsible for applying the tag.
  - "permanent": Deploy confirmed unique rules as permanent detections and
                 (optionally) clean up 'dksec-test' tagged rules. The adapter
                 handles cleanup.

Usage:
    from adapters.elastic.adapter import ElasticAdapter
    from pipeline.deploy import deploy_rules
    from storage.rule_store import RuleStore
    from pathlib import Path

    adapter = ElasticAdapter(kibana_url="https://kibana.lab.local", api_key="...")
    store = RuleStore(Path("catalogs"))
    rules = store.load_all("sigma")
    result = deploy_rules(adapter, rules, client=None, mode="test")
    print(f"Deployed {result.deployed_count} rules ({result.failed_count} failed)")
"""
from __future__ import annotations

from dataclasses import dataclass, field

from adapters.base import BaseAdapter
from core.ast_model import RuleAST


@dataclass
class DeployResult:
    """Summary of a single deploy run."""
    catalog: str
    mode: str            # "test" | "permanent"
    deployed_count: int
    failed_count: int
    errors: list[str] = field(default_factory=list)


def deploy_rules(
    adapter: BaseAdapter,
    rules: list[RuleAST],
    client,
    mode: str = "test",
) -> DeployResult:
    """
    Push rules to a SIEM via adapter.deploy().

    Per-rule failures are caught and recorded — deploy_rules never raises.
    It is the adapter's responsibility to apply the 'dksec-test' tag when
    mode='test' and to clean up tagged rules when mode='permanent'.

    Args:
        adapter:  A BaseAdapter with deploy() implemented
        rules:    List of RuleAST objects to deploy
        client:   SIEM API client (passed through to adapter.deploy())
        mode:     "test" (temporary, tagged) or "permanent"

    Returns:
        DeployResult with deployed_count, failed_count, and errors
    """
    deployed_count = 0
    failed_count = 0
    errors: list[str] = []

    for rule in rules:
        try:
            adapter.deploy(rule, client)
            deployed_count += 1
        except Exception as exc:  # noqa: BLE001
            failed_count += 1
            errors.append(f"{rule.id}: {exc}")

    return DeployResult(
        catalog=adapter.name,
        mode=mode,
        deployed_count=deployed_count,
        failed_count=failed_count,
        errors=errors,
    )
```

### Step 3: Run all tests — expect ~192 passing

```python
import subprocess, sys
r = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-q"], capture_output=True, text=True, cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec")
print(r.stdout, r.stderr)
```

### Step 4: Commit

```
git add pipeline/deploy.py tests/pipeline/test_deploy.py
git commit -m "feat: add pipeline/deploy.py

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Task 4: Integration tests + merge

**Files:**
- Create: `tests/pipeline/test_pipeline_integration.py`

### Step 1: Write 3 integration tests

```python
# tests/pipeline/test_pipeline_integration.py
"""
Integration tests: ingest → translate → compare full pipeline.
No live SIEM or git repo — all I/O through tmp_path stores.
"""
import uuid
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


def _make_ast(rule_id: str, catalog: str = "sigma", translated: str | None = None) -> RuleAST:
    return RuleAST(
        id=rule_id,
        catalog=catalog,
        name=f"Rule {rule_id}",
        description="",
        severity="medium",
        mitre_techniques=["attack.t1059.001"],
        event_categories=["process"],
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
    adapter.parse.side_effect = asts
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

    # Sigma: r1 is unique; r2 overlaps with elastic's e1 (same tokens)
    sigma_raws = [_make_raw("r1"), _make_raw("r2")]
    sigma_asts = [
        _make_ast("r1", "sigma", translated="process where process.name == 'unique.exe'"),
        _make_ast("r2", "sigma", translated="process where process.name == 'cmd.exe'"),
    ]
    sigma_adapter = _mock_adapter(sigma_raws, sigma_asts, name="sigma")

    elastic_raws = [_make_raw("e1")]
    elastic_asts = [_make_ast("e1", "elastic", translated="process where process.name == 'cmd.exe'")]
    elastic_adapter = _mock_adapter(elastic_raws, elastic_asts, name="elastic")

    ingest_catalog(sigma_adapter, store)
    translate_catalog(sigma_adapter, store)
    ingest_catalog(elastic_adapter, store)
    translate_catalog(elastic_adapter, store)

    sigma_rules = store.load_all("sigma")
    elastic_rules = store.load_all("elastic")

    result = compare_rules(sigma_rules, elastic_rules)

    # r1 unique (different query), r2 should overlap with e1
    assert result.catalog_a == "sigma"
    assert result.catalog_b == "elastic"
    unique_ids = {r.id for r in result.unique_a}
    assert "r1" in unique_ids


def test_ingest_translate_decide_pipeline(tmp_path):
    store = RuleStore(tmp_path)

    sigma_raws = [_make_raw("r1")]
    sigma_asts = [_make_ast("r1", "sigma", translated="process where process.name == 'unique_sigma.exe'")]
    sigma_adapter = _mock_adapter(sigma_raws, sigma_asts, name="sigma")

    elastic_raws = [_make_raw("e1")]
    elastic_asts = [_make_ast("e1", "elastic", translated="process where process.name == 'elastic.exe'")]
    elastic_adapter = _mock_adapter(elastic_raws, elastic_asts, name="elastic")

    ingest_catalog(sigma_adapter, store)
    translate_catalog(sigma_adapter, store)
    ingest_catalog(elastic_adapter, store)
    translate_catalog(elastic_adapter, store)

    sigma_rules = store.load_all("sigma")
    elastic_rules = store.load_all("elastic")

    compare_result = compare_rules(sigma_rules, elastic_rules)
    decisions = decide(compare_result)

    # r1 is unique → should be ADD
    assert decisions.get("r1") == "ADD"
```

### Step 2: Run full suite

```python
import subprocess, sys
r = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-q"], capture_output=True, text=True, cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec")
print(r.stdout, r.stderr)
```

Expected: ~195 tests passing

### Step 3: Commit

```
git add tests/pipeline/test_pipeline_integration.py
git commit -m "test: add Plan 5 pipeline integration tests

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

### Step 4: Merge to main

```
git checkout main
git merge plan5-pipeline --no-ff -m "feat: merge Plan 5 pipeline orchestration steps into main

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
python -m pytest tests/ -q
git branch -d plan5-pipeline
```
