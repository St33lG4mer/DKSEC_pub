# DKSec Refactor — Plan 3: Compare & Decide Pipeline

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `pipeline/compare.py` and `pipeline/decide.py` — the catalog-agnostic comparison engine that finds overlaps between two rule sets (via Jaccard similarity and optional alert co-firing data) and produces ADD/SKIP decisions for the rules to deploy.

**Architecture:** `compare_rules()` accepts two lists of `RuleAST` (catalog A and B) and optional alert data from a prior attack chain run. It returns a `CompareResult` containing matched overlap pairs and the unique rules from each catalog. `decide()` then maps every rule in catalog A to an ADD or SKIP decision. Both modules are pure Python with no external dependencies — all I/O is handled by the existing `RuleStore` and `ResultStore`.

**Tech Stack:** Python 3.10+, `pytest`, `unittest.mock`, `core.normalizer.jaccard`, `core.normalizer.extract_eql_tokens`, `storage.result_store.ResultStore`

---

## Pre-requisite

```
git checkout main
git pull
git checkout -b plan3-compare
```

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `pipeline/__init__.py` | Create | Package marker |
| `pipeline/compare.py` | Create | `OverlapPair`, `CompareResult` dataclasses + `compare_rules()` |
| `pipeline/decide.py` | Create | `decide(result: CompareResult) -> dict[str, str]` |
| `tests/pipeline/__init__.py` | Create | Package marker |
| `tests/pipeline/test_compare.py` | Create | All compare tests (logic-only + alert overlay) |
| `tests/pipeline/test_decide.py` | Create | All decide tests |

---

## Shared fixtures (used across multiple tasks)

These helper fixtures are defined in `tests/pipeline/test_compare.py` and reused. Reproduce in full in each task — never assume shared state.

```python
from core.ast_model import RuleAST
from core.normalizer import extract_eql_tokens

def _make_rule(
    rule_id: str,
    catalog: str,
    query: str = "",
    mitre: list[str] | None = None,
    translated: str | None = None,
) -> RuleAST:
    return RuleAST(
        id=rule_id,
        catalog=catalog,
        name=f"Rule {rule_id}",
        description="",
        severity="medium",
        mitre_techniques=mitre or [],
        event_categories=[],
        conditions=[],
        raw_query=query,
        language="eql",
        translated_query=translated,
        source_path="test",
        metadata={},
    )
```

---

## Task 1: Package setup + data types

**Files:**
- Create: `pipeline/__init__.py`
- Create: `pipeline/compare.py` (data types only — no `compare_rules` yet)
- Create: `tests/pipeline/__init__.py`
- Create: `tests/pipeline/test_compare.py` (data type tests only)

- [ ] **Step 1: Write failing tests**

```python
# tests/pipeline/test_compare.py
"""Tests for compare_rules() and related data types."""
import pytest
from core.ast_model import RuleAST
from pipeline.compare import OverlapPair, CompareResult


def _make_rule(
    rule_id: str,
    catalog: str,
    query: str = "",
    mitre: list[str] | None = None,
    translated: str | None = None,
) -> RuleAST:
    return RuleAST(
        id=rule_id,
        catalog=catalog,
        name=f"Rule {rule_id}",
        description="",
        severity="medium",
        mitre_techniques=mitre or [],
        event_categories=[],
        conditions=[],
        raw_query=query,
        language="eql",
        translated_query=translated,
        source_path="test",
        metadata={},
    )


# ---------------------------------------------------------------------------
# OverlapPair
# ---------------------------------------------------------------------------

def test_overlap_pair_to_dict_contains_ids():
    a = _make_rule("a1", "sigma")
    b = _make_rule("b1", "elastic")
    pair = OverlapPair(rule_a=a, rule_b=b, jaccard_score=0.5)
    d = pair.to_dict()
    assert d["rule_a_id"] == "a1"
    assert d["rule_b_id"] == "b1"
    assert d["jaccard_score"] == 0.5
    assert d["alert_confirmed"] is False


def test_overlap_pair_to_dict_alert_confirmed():
    a = _make_rule("a1", "sigma")
    b = _make_rule("b1", "elastic")
    pair = OverlapPair(rule_a=a, rule_b=b, jaccard_score=0.3, alert_confirmed=True)
    assert pair.to_dict()["alert_confirmed"] is True


def test_overlap_pair_to_dict_contains_names_and_catalogs():
    a = _make_rule("a1", "sigma")
    b = _make_rule("b1", "elastic")
    pair = OverlapPair(rule_a=a, rule_b=b, jaccard_score=0.4)
    d = pair.to_dict()
    assert d["rule_a_catalog"] == "sigma"
    assert d["rule_b_catalog"] == "elastic"
    assert "rule_a_name" in d
    assert "rule_b_name" in d


# ---------------------------------------------------------------------------
# CompareResult
# ---------------------------------------------------------------------------

def test_compare_result_to_storage_dicts():
    a = _make_rule("a1", "sigma")
    b = _make_rule("b1", "elastic")
    a2 = _make_rule("a2", "sigma")
    pair = OverlapPair(rule_a=a, rule_b=b, jaccard_score=0.6)
    result = CompareResult(
        overlaps=[pair],
        unique_a=[a2],
        unique_b=[b],
        confidence="logic-only",
        catalog_a="sigma",
        catalog_b="elastic",
    )
    overlaps_dicts, unique_a_dicts = result.to_storage_dicts()
    assert len(overlaps_dicts) == 1
    assert overlaps_dicts[0]["rule_a_id"] == "a1"
    assert len(unique_a_dicts) == 1
    assert unique_a_dicts[0]["id"] == "a2"


def test_compare_result_confidence_stored():
    result = CompareResult(
        overlaps=[],
        unique_a=[],
        unique_b=[],
        confidence="full",
        catalog_a="sigma",
        catalog_b="elastic",
    )
    assert result.confidence == "full"
```

- [ ] **Step 2: Run tests to verify they fail**

```
python -m pytest tests/pipeline/test_compare.py -v
```

Expected: `ModuleNotFoundError: No module named 'pipeline'`

- [ ] **Step 3: Create package markers and implement data types**

```python
# pipeline/__init__.py
# (empty)
```

```python
# tests/pipeline/__init__.py
# (empty)
```

```python
# pipeline/compare.py
"""Catalog-agnostic comparison engine."""
from __future__ import annotations

from dataclasses import dataclass, field

from core.ast_model import RuleAST


@dataclass
class OverlapPair:
    """A matched pair of rules from catalog A and catalog B."""
    rule_a: RuleAST
    rule_b: RuleAST
    jaccard_score: float
    alert_confirmed: bool = False

    def to_dict(self) -> dict:
        return {
            "rule_a_id": self.rule_a.id,
            "rule_a_name": self.rule_a.name,
            "rule_a_catalog": self.rule_a.catalog,
            "rule_b_id": self.rule_b.id,
            "rule_b_name": self.rule_b.name,
            "rule_b_catalog": self.rule_b.catalog,
            "jaccard_score": self.jaccard_score,
            "alert_confirmed": self.alert_confirmed,
        }


@dataclass
class CompareResult:
    """Output of compare_rules()."""
    overlaps: list[OverlapPair]
    unique_a: list[RuleAST]   # rules in A with no confirmed overlap in B
    unique_b: list[RuleAST]   # rules in B with no confirmed overlap in A
    confidence: str            # "full" | "logic-only"
    catalog_a: str
    catalog_b: str

    def to_storage_dicts(self) -> tuple[list[dict], list[dict]]:
        """Return (overlaps_dicts, unique_a_dicts) suitable for ResultStore."""
        return (
            [p.to_dict() for p in self.overlaps],
            [r.to_dict() for r in self.unique_a],
        )
```

- [ ] **Step 4: Run tests to verify they pass**

```
python -m pytest tests/pipeline/test_compare.py -v
```

Expected: all 5 tests PASS

- [ ] **Step 5: Run full suite**

```
python -m pytest tests/ -q
```

Expected: all 109 tests pass + 5 new = 114 pass

- [ ] **Step 6: Commit**

```
git add pipeline/__init__.py pipeline/compare.py tests/pipeline/__init__.py tests/pipeline/test_compare.py
git commit -m "feat: add pipeline package with OverlapPair and CompareResult data types

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Task 2: `compare_rules()` — logic-only mode

**Files:**
- Modify: `pipeline/compare.py` (add `compare_rules()`)
- Modify: `tests/pipeline/test_compare.py` (append logic-only tests)

- [ ] **Step 1: Append failing tests**

Append the following to `tests/pipeline/test_compare.py` (do NOT rewrite the file):

```python
from pipeline.compare import compare_rules


# ---------------------------------------------------------------------------
# compare_rules() — logic-only mode
# ---------------------------------------------------------------------------

def test_compare_empty_lists_return_empty_result():
    result = compare_rules([], [], threshold=0.15)
    assert result.overlaps == []
    assert result.unique_a == []
    assert result.unique_b == []
    assert result.confidence == "logic-only"


def test_compare_identical_queries_produce_overlap():
    query = 'process where process.name == "cmd.exe"'
    a = _make_rule("a1", "sigma", translated=query)
    b = _make_rule("b1", "elastic", translated=query)
    result = compare_rules([a], [b], threshold=0.15)
    assert len(result.overlaps) == 1
    assert result.overlaps[0].rule_a.id == "a1"
    assert result.overlaps[0].rule_b.id == "b1"
    assert result.overlaps[0].jaccard_score == pytest.approx(1.0)


def test_compare_unrelated_queries_no_overlap():
    a = _make_rule("a1", "sigma", translated='process where process.name == "cmd.exe"')
    b = _make_rule("b1", "elastic", translated='network where destination.port == 443')
    result = compare_rules([a], [b], threshold=0.15)
    assert result.overlaps == []
    assert len(result.unique_a) == 1
    assert len(result.unique_b) == 1


def test_compare_threshold_controls_overlap():
    # Build two rules with a moderate Jaccard score
    a = _make_rule("a1", "sigma", translated='process where process.name == "cmd.exe" and process.args == "/c"')
    b = _make_rule("b1", "elastic", translated='process where process.name == "cmd.exe" and user.name == "admin"')
    # They share some tokens but not all
    result_strict = compare_rules([a], [b], threshold=0.99)
    result_loose = compare_rules([a], [b], threshold=0.01)
    assert result_strict.overlaps == [] or result_loose.overlaps != []


def test_compare_unique_a_and_b_are_disjoint_from_overlaps():
    query = 'process where process.name == "cmd.exe"'
    a1 = _make_rule("a1", "sigma", translated=query)
    a2 = _make_rule("a2", "sigma", translated='file where file.name == "malware.exe"')
    b1 = _make_rule("b1", "elastic", translated=query)
    b2 = _make_rule("b2", "elastic", translated='network where destination.port == 4444')
    result = compare_rules([a1, a2], [b1, b2], threshold=0.15)
    overlap_a_ids = {p.rule_a.id for p in result.overlaps}
    overlap_b_ids = {p.rule_b.id for p in result.overlaps}
    unique_a_ids = {r.id for r in result.unique_a}
    unique_b_ids = {r.id for r in result.unique_b}
    assert overlap_a_ids.isdisjoint(unique_a_ids)
    assert overlap_b_ids.isdisjoint(unique_b_ids)


def test_compare_uses_translated_query_if_available():
    # raw_query is junk; translated_query is the real EQL
    a = _make_rule("a1", "sigma", query="sigma: junk", translated='process where process.name == "cmd.exe"')
    b = _make_rule("b1", "elastic", query="sigma: junk", translated='process where process.name == "cmd.exe"')
    result = compare_rules([a], [b], threshold=0.15)
    assert len(result.overlaps) == 1


def test_compare_falls_back_to_raw_query_when_no_translated():
    a = _make_rule("a1", "sigma", query='process where process.name == "cmd.exe"')
    b = _make_rule("b1", "elastic", query='process where process.name == "cmd.exe"')
    result = compare_rules([a], [b], threshold=0.15)
    assert len(result.overlaps) == 1


def test_compare_many_to_many():
    queries = [
        'process where process.name == "cmd.exe"',
        'network where destination.port == 4444',
        'file where file.name == "malware.dll"',
    ]
    rules_a = [_make_rule(f"a{i}", "sigma", translated=q) for i, q in enumerate(queries)]
    rules_b = [_make_rule(f"b{i}", "elastic", translated=q) for i, q in enumerate(queries)]
    result = compare_rules(rules_a, rules_b, threshold=0.15)
    assert len(result.overlaps) == 3
    assert result.unique_a == []
    assert result.unique_b == []


def test_compare_catalog_names_in_result():
    a = _make_rule("a1", "sigma")
    b = _make_rule("b1", "elastic")
    result = compare_rules([a], [b], threshold=0.15)
    assert result.catalog_a == "sigma"
    assert result.catalog_b == "elastic"
```

- [ ] **Step 2: Run to verify failures**

```
python -m pytest tests/pipeline/test_compare.py -v -k "compare_"
```

Expected: `AttributeError` or `ImportError` for `compare_rules`

- [ ] **Step 3: Implement `compare_rules()`**

Add to `pipeline/compare.py` after the existing dataclasses:

```python
from core.normalizer import extract_eql_tokens, jaccard


def _tokens_for(rule: RuleAST) -> frozenset:
    """Extract comparison tokens. Prefer translated_query; fall back to raw_query."""
    query = rule.translated_query if rule.translated_query is not None else rule.raw_query
    return extract_eql_tokens(query)


def _should_compare(rule_a: RuleAST, rule_b: RuleAST, tokens_a: frozenset, tokens_b: frozenset) -> bool:
    """
    Pre-filter: only compute Jaccard if rules share at least one MITRE technique,
    or their token sets have a non-empty intersection (fast to check).
    This avoids O(N²) full computation on totally unrelated rule pairs.
    """
    if rule_a.mitre_techniques and rule_b.mitre_techniques:
        if set(rule_a.mitre_techniques) & set(rule_b.mitre_techniques):
            return True
    return bool(tokens_a & tokens_b)


def compare_rules(
    rules_a: list[RuleAST],
    rules_b: list[RuleAST],
    alerts: list[dict] | None = None,
    threshold: float = 0.15,
) -> "CompareResult":
    """
    Compare two rule sets and return overlaps + unique rules.

    Logic-only mode (alerts=None):
        - Extract tokens from each rule's translated_query (or raw_query fallback)
        - Pre-filter candidate pairs by shared tokens or MITRE techniques
        - Compute Jaccard similarity for each candidate pair
        - Pairs >= threshold → overlap

    Full mode (alerts provided):
        - Same logic pass first
        - Then mark pairs as alert_confirmed if both rules fired on the same scenario
        - A pair is an overlap if EITHER the logic OR alert signal confirms it

    confidence is "full" when alerts is not None, "logic-only" otherwise.
    """
    if not rules_a or not rules_b:
        catalog_a = rules_a[0].catalog if rules_a else (rules_b[0].catalog if rules_b else "")
        catalog_b = rules_b[0].catalog if rules_b else (rules_a[0].catalog if rules_a else "")
        return CompareResult(
            overlaps=[],
            unique_a=list(rules_a),
            unique_b=list(rules_b),
            confidence="logic-only" if alerts is None else "full",
            catalog_a=catalog_a,
            catalog_b=catalog_b,
        )

    catalog_a = rules_a[0].catalog
    catalog_b = rules_b[0].catalog

    # Pre-compute tokens
    tokens_a = {r.id: _tokens_for(r) for r in rules_a}
    tokens_b = {r.id: _tokens_for(r) for r in rules_b}

    # Build alert co-firing index: scenario_id → set of rule_ids that fired
    scenario_to_rules: dict[str, set[str]] = {}
    if alerts:
        for alert in alerts:
            scenario_id = alert.get("scenario_id", "")
            rule_id = alert.get("rule_id", "")
            if scenario_id and rule_id:
                scenario_to_rules.setdefault(scenario_id, set()).add(rule_id)

    # For each pair, compute overlap
    overlap_pairs: list[OverlapPair] = []
    overlapped_a_ids: set[str] = set()
    overlapped_b_ids: set[str] = set()

    for a in rules_a:
        for b in rules_b:
            ta, tb = tokens_a[a.id], tokens_b[b.id]

            # Logic signal
            logic_overlap = False
            score = 0.0
            if _should_compare(a, b, ta, tb):
                score = jaccard(ta, tb)
                logic_overlap = score >= threshold

            # Alert signal
            alert_confirmed = False
            if alerts is not None:
                for fired_ids in scenario_to_rules.values():
                    if a.id in fired_ids and b.id in fired_ids:
                        alert_confirmed = True
                        break

            if logic_overlap or alert_confirmed:
                overlap_pairs.append(
                    OverlapPair(
                        rule_a=a,
                        rule_b=b,
                        jaccard_score=score,
                        alert_confirmed=alert_confirmed,
                    )
                )
                overlapped_a_ids.add(a.id)
                overlapped_b_ids.add(b.id)

    unique_a = [r for r in rules_a if r.id not in overlapped_a_ids]
    unique_b = [r for r in rules_b if r.id not in overlapped_b_ids]
    confidence = "logic-only" if alerts is None else "full"

    return CompareResult(
        overlaps=overlap_pairs,
        unique_a=unique_a,
        unique_b=unique_b,
        confidence=confidence,
        catalog_a=catalog_a,
        catalog_b=catalog_b,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

```
python -m pytest tests/pipeline/test_compare.py -v
```

Expected: all tests PASS

- [ ] **Step 5: Run full suite**

```
python -m pytest tests/ -q
```

Expected: all previous tests + new tests pass

- [ ] **Step 6: Commit**

```
git add pipeline/compare.py tests/pipeline/test_compare.py
git commit -m "feat: implement compare_rules() logic-only mode

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Task 3: `compare_rules()` — alert overlay mode

**Files:**
- Modify: `tests/pipeline/test_compare.py` (append alert overlay tests only — `compare_rules()` already handles alerts)

- [ ] **Step 1: Append failing tests**

Append to `tests/pipeline/test_compare.py`:

```python
# ---------------------------------------------------------------------------
# compare_rules() — alert overlay mode
# ---------------------------------------------------------------------------

def test_compare_alert_confirmed_sets_confidence_full():
    a = _make_rule("a1", "sigma", translated='process where process.name == "cmd.exe"')
    b = _make_rule("b1", "elastic", translated='network where destination.port == 443')
    # No logic overlap, but both fired on same scenario
    alerts = [
        {"rule_id": "a1", "catalog": "sigma", "scenario_id": "t1059"},
        {"rule_id": "b1", "catalog": "elastic", "scenario_id": "t1059"},
    ]
    result = compare_rules([a], [b], alerts=alerts, threshold=0.15)
    assert result.confidence == "full"


def test_compare_alert_co_firing_produces_overlap_even_below_threshold():
    a = _make_rule("a1", "sigma", translated='process where process.name == "cmd.exe"')
    b = _make_rule("b1", "elastic", translated='network where destination.port == 443')
    # These queries have zero token overlap — no logic overlap
    alerts = [
        {"rule_id": "a1", "catalog": "sigma", "scenario_id": "t1059"},
        {"rule_id": "b1", "catalog": "elastic", "scenario_id": "t1059"},
    ]
    result = compare_rules([a], [b], alerts=alerts, threshold=0.15)
    assert len(result.overlaps) == 1
    assert result.overlaps[0].alert_confirmed is True
    assert result.overlaps[0].jaccard_score == pytest.approx(0.0)


def test_compare_different_scenarios_no_alert_overlap():
    a = _make_rule("a1", "sigma", translated='process where process.name == "cmd.exe"')
    b = _make_rule("b1", "elastic", translated='network where destination.port == 443')
    # Each fires in a different scenario — no co-firing
    alerts = [
        {"rule_id": "a1", "catalog": "sigma", "scenario_id": "t1059"},
        {"rule_id": "b1", "catalog": "elastic", "scenario_id": "t1021"},
    ]
    result = compare_rules([a], [b], alerts=alerts, threshold=0.15)
    # No logic overlap, no co-firing → no overlap
    assert result.overlaps == []
    assert len(result.unique_a) == 1
    assert len(result.unique_b) == 1


def test_compare_logic_overlap_also_marked_not_alert_confirmed():
    query = 'process where process.name == "cmd.exe"'
    a = _make_rule("a1", "sigma", translated=query)
    b = _make_rule("b1", "elastic", translated=query)
    # Provide alerts but rules do NOT co-fire
    alerts = [
        {"rule_id": "a1", "catalog": "sigma", "scenario_id": "t1059"},
        {"rule_id": "b1", "catalog": "elastic", "scenario_id": "t1021"},
    ]
    result = compare_rules([a], [b], alerts=alerts, threshold=0.15)
    assert len(result.overlaps) == 1
    assert result.overlaps[0].alert_confirmed is False
    assert result.overlaps[0].jaccard_score == pytest.approx(1.0)


def test_compare_both_signals_sets_alert_confirmed_true():
    query = 'process where process.name == "cmd.exe"'
    a = _make_rule("a1", "sigma", translated=query)
    b = _make_rule("b1", "elastic", translated=query)
    alerts = [
        {"rule_id": "a1", "catalog": "sigma", "scenario_id": "t1059"},
        {"rule_id": "b1", "catalog": "elastic", "scenario_id": "t1059"},
    ]
    result = compare_rules([a], [b], alerts=alerts, threshold=0.15)
    assert len(result.overlaps) == 1
    assert result.overlaps[0].alert_confirmed is True
    assert result.overlaps[0].jaccard_score == pytest.approx(1.0)


def test_compare_no_alerts_gives_logic_only_confidence():
    a = _make_rule("a1", "sigma", translated='process where process.name == "cmd.exe"')
    b = _make_rule("b1", "elastic", translated='process where process.name == "cmd.exe"')
    result = compare_rules([a], [b])  # no alerts kwarg
    assert result.confidence == "logic-only"


def test_compare_empty_alerts_list_gives_full_confidence():
    a = _make_rule("a1", "sigma", translated='process where process.name == "cmd.exe"')
    b = _make_rule("b1", "elastic", translated='process where process.name == "cmd.exe"')
    result = compare_rules([a], [b], alerts=[])  # explicit empty list = "full" mode
    assert result.confidence == "full"
```

- [ ] **Step 2: Run to verify they pass (implementation already handles alerts)**

```
python -m pytest tests/pipeline/test_compare.py -v -k "alert"
```

Expected: all 7 alert tests PASS (compare_rules already handles alerts from Task 2)

If any fail, the logic in compare_rules needs to be adjusted — see notes in Task 2 Step 3.

- [ ] **Step 3: Run full suite**

```
python -m pytest tests/ -q
```

Expected: all tests pass

- [ ] **Step 4: Commit**

```
git add tests/pipeline/test_compare.py
git commit -m "test: add compare_rules() alert overlay tests

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Task 4: `pipeline/decide.py`

**Files:**
- Create: `pipeline/decide.py`
- Create: `tests/pipeline/test_decide.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/pipeline/test_decide.py
"""Tests for decide()."""
import pytest
from core.ast_model import RuleAST
from pipeline.compare import CompareResult, OverlapPair
from pipeline.decide import decide


def _make_rule(
    rule_id: str,
    catalog: str,
    query: str = "",
    mitre: list[str] | None = None,
    translated: str | None = None,
) -> RuleAST:
    return RuleAST(
        id=rule_id,
        catalog=catalog,
        name=f"Rule {rule_id}",
        description="",
        severity="medium",
        mitre_techniques=mitre or [],
        event_categories=[],
        conditions=[],
        raw_query=query,
        language="eql",
        translated_query=translated,
        source_path="test",
        metadata={},
    )


def _make_result(overlaps, unique_a, unique_b, confidence="logic-only"):
    return CompareResult(
        overlaps=overlaps,
        unique_a=unique_a,
        unique_b=unique_b,
        confidence=confidence,
        catalog_a="sigma",
        catalog_b="elastic",
    )


# ---------------------------------------------------------------------------
# decide() tests
# ---------------------------------------------------------------------------

def test_decide_unique_a_rules_get_add():
    a1 = _make_rule("a1", "sigma")
    result = _make_result(overlaps=[], unique_a=[a1], unique_b=[])
    decisions = decide(result)
    assert decisions["a1"] == "ADD"


def test_decide_overlapping_a_rules_get_skip():
    a1 = _make_rule("a1", "sigma")
    b1 = _make_rule("b1", "elastic")
    pair = OverlapPair(rule_a=a1, rule_b=b1, jaccard_score=0.8)
    result = _make_result(overlaps=[pair], unique_a=[], unique_b=[])
    decisions = decide(result)
    assert decisions["a1"] == "SKIP"


def test_decide_covers_all_rules_in_a():
    a1 = _make_rule("a1", "sigma")
    a2 = _make_rule("a2", "sigma")
    a3 = _make_rule("a3", "sigma")
    b1 = _make_rule("b1", "elastic")
    pair = OverlapPair(rule_a=a1, rule_b=b1, jaccard_score=0.8)
    result = _make_result(overlaps=[pair], unique_a=[a2, a3], unique_b=[])
    decisions = decide(result)
    assert set(decisions.keys()) == {"a1", "a2", "a3"}
    assert decisions["a1"] == "SKIP"
    assert decisions["a2"] == "ADD"
    assert decisions["a3"] == "ADD"


def test_decide_empty_returns_empty():
    result = _make_result(overlaps=[], unique_a=[], unique_b=[])
    assert decide(result) == {}


def test_decide_does_not_include_b_rules():
    b1 = _make_rule("b1", "elastic")
    result = _make_result(overlaps=[], unique_a=[], unique_b=[b1])
    decisions = decide(result)
    assert "b1" not in decisions


def test_decide_rule_in_multiple_overlaps_gets_skip_once():
    # a1 overlaps with both b1 and b2 — should still be SKIP (not duplicated)
    a1 = _make_rule("a1", "sigma")
    b1 = _make_rule("b1", "elastic")
    b2 = _make_rule("b2", "elastic")
    pair1 = OverlapPair(rule_a=a1, rule_b=b1, jaccard_score=0.9)
    pair2 = OverlapPair(rule_a=a1, rule_b=b2, jaccard_score=0.7)
    result = _make_result(overlaps=[pair1, pair2], unique_a=[], unique_b=[])
    decisions = decide(result)
    assert decisions["a1"] == "SKIP"
    assert len([k for k, v in decisions.items() if k == "a1"]) == 1  # no duplicates


def test_decide_add_count_matches_unique_a():
    rules_a = [_make_rule(f"a{i}", "sigma") for i in range(5)]
    result = _make_result(overlaps=[], unique_a=rules_a, unique_b=[])
    decisions = decide(result)
    add_count = sum(1 for v in decisions.values() if v == "ADD")
    assert add_count == 5


def test_decide_skip_count_matches_distinct_overlapping_a_rules():
    a1 = _make_rule("a1", "sigma")
    a2 = _make_rule("a2", "sigma")
    b1 = _make_rule("b1", "elastic")
    b2 = _make_rule("b2", "elastic")
    pair1 = OverlapPair(rule_a=a1, rule_b=b1, jaccard_score=0.9)
    pair2 = OverlapPair(rule_a=a2, rule_b=b2, jaccard_score=0.8)
    result = _make_result(overlaps=[pair1, pair2], unique_a=[], unique_b=[])
    decisions = decide(result)
    skip_count = sum(1 for v in decisions.values() if v == "SKIP")
    assert skip_count == 2
```

- [ ] **Step 2: Run to verify failures**

```
python -m pytest tests/pipeline/test_decide.py -v
```

Expected: `ModuleNotFoundError: No module named 'pipeline.decide'`

- [ ] **Step 3: Implement `decide()`**

```python
# pipeline/decide.py
"""
Produce ADD / SKIP decisions for rules in catalog A based on comparison results.

ADD  — rule has no confirmed overlap with any rule in catalog B (add to SIEM)
SKIP — rule overlaps with at least one rule in catalog B (already covered)
"""
from __future__ import annotations

from pipeline.compare import CompareResult


def decide(result: CompareResult) -> dict[str, str]:
    """
    Return a decision for every rule in catalog A.

    Returns:
        dict mapping rule_id → "ADD" | "SKIP"
    """
    decisions: dict[str, str] = {}

    # Rules in unique_a → ADD
    for rule in result.unique_a:
        decisions[rule.id] = "ADD"

    # Rules in overlaps (catalog A side) → SKIP
    for pair in result.overlaps:
        decisions[pair.rule_a.id] = "SKIP"

    return decisions
```

- [ ] **Step 4: Run tests to verify they pass**

```
python -m pytest tests/pipeline/test_decide.py -v
```

Expected: all 8 tests PASS

- [ ] **Step 5: Run full suite**

```
python -m pytest tests/ -q
```

Expected: all tests pass

- [ ] **Step 6: Commit**

```
git add pipeline/decide.py tests/pipeline/test_decide.py
git commit -m "feat: add pipeline/decide.py with decide() function

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Task 5: Integration test + full suite verification + merge

**Files:**
- Create: `tests/pipeline/test_integration.py`

This task wires the full compare→decide→storage pipeline together using in-memory fixtures. No live SIEM or filesystem access.

- [ ] **Step 1: Write integration tests**

```python
# tests/pipeline/test_integration.py
"""
Integration test: compare → decide → ResultStore round-trip.
Uses in-memory temp dirs — no live SIEM or filesystem state.
"""
import json
import pytest
import tempfile
from pathlib import Path

from core.ast_model import RuleAST
from pipeline.compare import compare_rules, CompareResult
from pipeline.decide import decide
from storage.result_store import ResultStore


def _make_rule(
    rule_id: str,
    catalog: str,
    query: str = "",
    translated: str | None = None,
    mitre: list[str] | None = None,
) -> RuleAST:
    return RuleAST(
        id=rule_id,
        catalog=catalog,
        name=f"Rule {rule_id}",
        description="test rule",
        severity="medium",
        mitre_techniques=mitre or [],
        event_categories=[],
        conditions=[],
        raw_query=query,
        language="eql",
        translated_query=translated,
        source_path="test",
        metadata={},
    )


SHARED_QUERY = 'process where process.name == "cmd.exe" and process.args == "/c whoami"'
UNIQUE_SIGMA = 'process where process.name == "mshta.exe" and process.args like~ "*.hta"'
UNIQUE_ELASTIC = 'network where destination.port == 4444 and process.name == "powershell.exe"'


@pytest.fixture
def store(tmp_path):
    return ResultStore(tmp_path)


def test_full_pipeline_logic_only(store):
    """compare → decide → store round trip, logic-only mode."""
    sigma_rules = [
        _make_rule("s1", "sigma", translated=SHARED_QUERY),
        _make_rule("s2", "sigma", translated=UNIQUE_SIGMA),
    ]
    elastic_rules = [
        _make_rule("e1", "elastic", translated=SHARED_QUERY),
        _make_rule("e2", "elastic", translated=UNIQUE_ELASTIC),
    ]

    result = compare_rules(sigma_rules, elastic_rules, threshold=0.15)
    assert result.confidence == "logic-only"
    assert len(result.overlaps) == 1
    assert result.overlaps[0].rule_a.id == "s1"
    assert len(result.unique_a) == 1
    assert result.unique_a[0].id == "s2"

    decisions = decide(result)
    assert decisions["s1"] == "SKIP"
    assert decisions["s2"] == "ADD"

    # Persist and reload
    overlaps_dicts, unique_a_dicts = result.to_storage_dicts()
    store.save_overlaps("sigma", "elastic", overlaps_dicts)
    store.save_unique("sigma", "elastic", unique_a_dicts)
    store.save_decisions("sigma", "elastic", decisions)

    loaded_overlaps = store.load_overlaps("sigma", "elastic")
    loaded_unique = store.load_unique("sigma", "elastic")
    loaded_decisions = store.load_decisions("sigma", "elastic")

    assert len(loaded_overlaps) == 1
    assert loaded_overlaps[0]["rule_a_id"] == "s1"
    assert len(loaded_unique) == 1
    assert loaded_unique[0]["id"] == "s2"
    assert loaded_decisions["s1"] == "SKIP"
    assert loaded_decisions["s2"] == "ADD"


def test_full_pipeline_with_alert_overlay(store):
    """compare → decide → store round trip, alert overlay mode."""
    sigma_rules = [
        _make_rule("s1", "sigma", translated='process where process.name == "cmd.exe"'),
        _make_rule("s2", "sigma", translated=UNIQUE_SIGMA),
    ]
    elastic_rules = [
        _make_rule("e1", "elastic", translated='network where destination.port == 443'),  # different logic
        _make_rule("e2", "elastic", translated=UNIQUE_ELASTIC),
    ]
    # s1 and e1 have no logic overlap but co-fired on same scenario
    alerts = [
        {"rule_id": "s1", "catalog": "sigma", "scenario_id": "t1059"},
        {"rule_id": "e1", "catalog": "elastic", "scenario_id": "t1059"},
    ]

    result = compare_rules(sigma_rules, elastic_rules, alerts=alerts, threshold=0.15)
    assert result.confidence == "full"
    assert len(result.overlaps) == 1
    assert result.overlaps[0].alert_confirmed is True

    decisions = decide(result)
    assert decisions["s1"] == "SKIP"
    assert decisions["s2"] == "ADD"


def test_full_pipeline_all_unique(store):
    """When no rules overlap, all sigma rules → ADD."""
    sigma_rules = [_make_rule(f"s{i}", "sigma", translated=UNIQUE_SIGMA) for i in range(3)]
    elastic_rules = [_make_rule(f"e{i}", "elastic", translated=UNIQUE_ELASTIC) for i in range(3)]

    result = compare_rules(sigma_rules, elastic_rules, threshold=0.15)
    assert result.overlaps == []
    decisions = decide(result)
    assert all(v == "ADD" for v in decisions.values())
    assert len(decisions) == 3


def test_full_pipeline_all_overlap(store):
    """When every sigma rule overlaps, all → SKIP."""
    sigma_rules = [_make_rule(f"s{i}", "sigma", translated=SHARED_QUERY) for i in range(3)]
    elastic_rules = [_make_rule(f"e{i}", "elastic", translated=SHARED_QUERY) for i in range(3)]

    result = compare_rules(sigma_rules, elastic_rules, threshold=0.15)
    decisions = decide(result)
    assert all(v == "SKIP" for v in decisions.values())
    assert len(decisions) == 3
```

- [ ] **Step 2: Run integration tests**

```
python -m pytest tests/pipeline/test_integration.py -v
```

Expected: all 4 integration tests PASS

- [ ] **Step 3: Run full test suite and record count**

```
python -m pytest tests/ -q
```

Expected: all tests pass (109 original + new pipeline tests ≈ 140+ total)

- [ ] **Step 4: Commit integration tests**

```
git add tests/pipeline/test_integration.py
git commit -m "test: add pipeline integration tests (compare → decide → ResultStore)

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

- [ ] **Step 5: Merge to main**

```
git checkout main
git merge --no-ff plan3-compare -m "feat: Plan 3 — compare and decide pipeline

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
git branch -d plan3-compare
```

- [ ] **Step 6: Verify on main**

```
python -m pytest tests/ -q
```

Expected: all tests pass on main

---

## Self-Review Notes

**Spec coverage:**
- ✅ `pipeline/compare.py` — catalog-agnostic Jaccard comparison (spec §Comparison Logic)
- ✅ Logic-only fallback mode with `confidence: "logic-only"` label (spec §Fallback)
- ✅ Alert co-firing signal — both signals merged (spec Mode 1)
- ✅ `output/overlaps/` and `output/unique/` via `ResultStore` (spec §Pipeline Step Contracts)
- ✅ `pipeline/decide.py` — ADD/SKIP decisions (spec §decide step)
- ✅ Pre-filter optimization via shared tokens/MITRE before full Jaccard (spec §Comparison Logic step 1)
- ✅ threshold parameter default 0.15 (spec §CLI: `--threshold 0.15`)
- ✅ `confidence` field on `CompareResult` (spec §Mode 2: "labelled logic-only in output")

**Type consistency:**
- `OverlapPair.to_dict()` uses `rule_a_id`, `rule_b_id` — consistent with `ResultStore.save_overlaps()` input
- `CompareResult.to_storage_dicts()` returns `(list[dict], list[dict])` — used in integration test
- `decide()` takes `CompareResult` — consistent with Task 4 and integration test
- `_tokens_for()` returns `frozenset` — compatible with `jaccard(a, b)` which expects `frozenset`
