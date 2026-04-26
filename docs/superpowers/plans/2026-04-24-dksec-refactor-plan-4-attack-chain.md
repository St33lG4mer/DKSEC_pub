# DKSec Refactor — Plan 4: Attack Chain

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `attack/base.py`, `attack/sliver.py`, `attack/atomic.py`, and `pipeline/attack_chain.py` — the attack chain module that runs MITRE ATT&CK scenarios against a SIEM, collects which rules fired per scenario, and produces alert data that `compare_rules()` can consume.

**Architecture:** `AttackRunner` is an abstract base class with two concrete stubs — `SliverRunner` (wraps existing `sliver_test_harness/` scenario definitions) and `AtomicRunner` (scaffold for Atomic Red Team). `pipeline/attack_chain.py` orchestrates one or more runners, merges their `ScenarioResult` outputs into the alert dict format that `compare_rules(alerts=...)` already expects, and persists them via `ResultStore.save_alerts()`. Neither runner requires live C2 infrastructure: if unconfigured, `run_scenario()` raises `RuntimeError` cleanly. Tests use mocks only.

**Tech Stack:** Python 3.10+, `pytest`, `unittest.mock`, `storage.result_store.ResultStore`, `pipeline.compare.compare_rules`

---

## Pre-requisite

```
git checkout main
git pull
git checkout -b plan4-attack
```

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `attack/__init__.py` | Create | Package marker |
| `attack/base.py` | Create | `AttackScenario`, `ScenarioResult`, `AttackRunner` ABC |
| `attack/sliver.py` | Create | `SliverRunner(AttackRunner)` — loads from `sliver_test_harness/scenarios.py` |
| `attack/atomic.py` | Create | `AtomicRunner(AttackRunner)` — Atomic Red Team scaffold |
| `pipeline/attack_chain.py` | Create | `run_attack_chain()` — orchestrates runners, saves alerts |
| `tests/attack/__init__.py` | Create | Package marker |
| `tests/attack/test_base.py` | Create | Data type + ABC tests |
| `tests/attack/test_sliver.py` | Create | SliverRunner tests |
| `tests/attack/test_atomic.py` | Create | AtomicRunner tests |
| `tests/pipeline/test_attack_chain.py` | Create | attack_chain orchestrator tests |
| `tests/pipeline/test_attack_integration.py` | Create | end-to-end: mock runner → attack_chain → compare_rules |

---

## Shared fixtures (used across multiple tasks)

These helpers are defined per-file — never assume shared state between test modules.

```python
from attack.base import AttackScenario, ScenarioResult

def _make_scenario(sid: str = "S1", techniques: list[str] | None = None) -> AttackScenario:
    return AttackScenario(
        id=sid,
        description=f"Scenario {sid}",
        mitre_techniques=techniques or ["T1059.001"],
        steps=[{"name": "step1", "kind": "shell", "command": "cmd.exe", "args": []}],
    )

def _make_result(sid: str = "S1", fired: list[str] | None = None) -> ScenarioResult:
    return ScenarioResult(
        scenario_id=sid,
        mitre_techniques=["T1059.001"],
        fired_rule_ids=fired or ["rule-1", "rule-2"],
        raw_alert_count=len(fired or ["rule-1", "rule-2"]),
    )
```

---

## Task 1: `attack/` package — data types + `AttackRunner` ABC

**Files:**
- Create: `attack/__init__.py`
- Create: `attack/base.py`
- Create: `tests/attack/__init__.py`
- Create: `tests/attack/test_base.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/attack/test_base.py
"""Tests for AttackScenario, ScenarioResult, and AttackRunner ABC."""
import pytest
from attack.base import AttackRunner, AttackScenario, ScenarioResult


def _make_scenario(sid: str = "S1", techniques: list[str] | None = None) -> AttackScenario:
    return AttackScenario(
        id=sid,
        description=f"Scenario {sid}",
        mitre_techniques=techniques or ["T1059.001"],
        steps=[{"name": "step1", "kind": "shell", "command": "cmd.exe", "args": []}],
    )


def _make_result(sid: str = "S1", fired: list[str] | None = None) -> ScenarioResult:
    return ScenarioResult(
        scenario_id=sid,
        mitre_techniques=["T1059.001"],
        fired_rule_ids=fired or ["rule-1", "rule-2"],
        raw_alert_count=len(fired or ["rule-1", "rule-2"]),
    )


# ---------------------------------------------------------------------------
# AttackScenario
# ---------------------------------------------------------------------------

def test_scenario_stores_fields():
    s = _make_scenario("S1", ["T1059.001", "T1082"])
    assert s.id == "S1"
    assert s.description == "Scenario S1"
    assert s.mitre_techniques == ["T1059.001", "T1082"]
    assert len(s.steps) == 1


# ---------------------------------------------------------------------------
# ScenarioResult
# ---------------------------------------------------------------------------

def test_result_stores_fields():
    r = _make_result("S1", ["r1", "r2", "r3"])
    assert r.scenario_id == "S1"
    assert r.fired_rule_ids == ["r1", "r2", "r3"]
    assert r.raw_alert_count == 3
    assert r.error is None


def test_result_error_field_defaults_none():
    r = ScenarioResult(
        scenario_id="S1",
        mitre_techniques=[],
        fired_rule_ids=[],
        raw_alert_count=0,
    )
    assert r.error is None


def test_result_error_field_can_be_set():
    r = ScenarioResult(
        scenario_id="S1",
        mitre_techniques=[],
        fired_rule_ids=[],
        raw_alert_count=0,
        error="Sliver C2 unreachable",
    )
    assert r.error == "Sliver C2 unreachable"


def test_to_alert_dicts_returns_one_dict_per_fired_rule():
    r = _make_result("S1", ["rule-a", "rule-b"])
    alerts = r.to_alert_dicts()
    assert len(alerts) == 2


def test_to_alert_dicts_contains_rule_id_and_scenario_id():
    r = _make_result("T1059", ["rule-x"])
    alerts = r.to_alert_dicts()
    assert alerts[0]["rule_id"] == "rule-x"
    assert alerts[0]["scenario_id"] == "T1059"


def test_to_alert_dicts_empty_fired_returns_empty():
    r = _make_result("S1", [])
    assert r.to_alert_dicts() == []


# ---------------------------------------------------------------------------
# AttackRunner ABC enforcement
# ---------------------------------------------------------------------------

def test_attack_runner_is_abstract():
    with pytest.raises(TypeError):
        AttackRunner()  # type: ignore
```

- [ ] **Step 2: Run tests to verify they fail**

```python
import subprocess, sys
r = subprocess.run([sys.executable, "-m", "pytest", "tests/attack/test_base.py", "-v"], capture_output=True, text=True, cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec")
print(r.stdout, r.stderr)
```

Expected: `ModuleNotFoundError: No module named 'attack'`

- [ ] **Step 3: Create package markers**

`attack/__init__.py` — empty file.
`tests/attack/__init__.py` — empty file.

- [ ] **Step 4: Create `attack/base.py`**

```python
# attack/base.py
"""Abstract base class and data types for attack chain runners."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class AttackScenario:
    """A MITRE ATT&CK scenario definition with one or more execution steps."""
    id: str
    description: str
    mitre_techniques: list[str]  # e.g. ["T1059.001", "T1082"]
    steps: list[dict]            # raw step definitions (runner-specific)


@dataclass
class ScenarioResult:
    """Result from executing one AttackScenario against a live SIEM."""
    scenario_id: str
    mitre_techniques: list[str]   # techniques actually exercised
    fired_rule_ids: list[str]     # SIEM rule IDs/names that produced alerts
    raw_alert_count: int
    error: str | None = None      # set if runner failed, None on success

    def to_alert_dicts(self) -> list[dict]:
        """
        Convert to the alert dict format consumed by compare_rules(alerts=...).

        Each dict has:
          rule_id     — the SIEM rule that fired
          scenario_id — the scenario that triggered it
        """
        return [
            {"rule_id": rid, "scenario_id": self.scenario_id}
            for rid in self.fired_rule_ids
        ]


class AttackRunner(ABC):
    """
    Abstract base class for attack chain runners.

    Implementations:
        SliverRunner  — executes Sliver C2 scenarios
        AtomicRunner  — executes Atomic Red Team tests
    """

    @abstractmethod
    def run_scenario(self, scenario: AttackScenario) -> ScenarioResult:
        """Execute a single scenario and return which SIEM rules fired."""

    @abstractmethod
    def list_scenarios(self) -> list[AttackScenario]:
        """Return the list of scenarios this runner can execute."""
```

- [ ] **Step 5: Run tests to verify they pass**

```python
import subprocess, sys
r = subprocess.run([sys.executable, "-m", "pytest", "tests/attack/test_base.py", "-v"], capture_output=True, text=True, cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec")
print(r.stdout, r.stderr)
```

Expected: 8 tests PASS

- [ ] **Step 6: Run full suite**

```python
import subprocess, sys
r = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-q"], capture_output=True, text=True, cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec")
print(r.stdout, r.stderr)
```

Expected: all prior 142 + 8 new = 150 pass

- [ ] **Step 7: Commit**

```python
import subprocess
r = subprocess.run(
    ["git", "add", "attack/__init__.py", "attack/base.py", "tests/attack/__init__.py", "tests/attack/test_base.py"],
    cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec", capture_output=True, text=True
)
r2 = subprocess.run(
    ["git", "commit", "-m", "feat: add attack package with AttackScenario, ScenarioResult, AttackRunner\n\nCo-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"],
    cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec", capture_output=True, text=True
)
print(r.stdout, r.stderr, r2.stdout, r2.stderr)
```

---

## Task 2: `attack/sliver.py` — SliverRunner

**Files:**
- Create: `attack/sliver.py`
- Create: `tests/attack/test_sliver.py`

`SliverRunner` loads scenario definitions from `sliver_test_harness/scenarios.py` (the existing `SCENARIOS` dict). The constructor accepts an optional `scenarios` dict for testability (avoids importing the full harness in tests). `run_scenario()` raises `RuntimeError` if `config["host"]` is not set — it never silently no-ops.

- [ ] **Step 1: Write failing tests**

```python
# tests/attack/test_sliver.py
"""Tests for SliverRunner."""
import pytest
from attack.base import AttackScenario, ScenarioResult
from attack.sliver import SliverRunner


# Minimal fake scenarios dict (same schema as sliver_test_harness/scenarios.py)
FAKE_SCENARIOS = {
    "S1_recon": {
        "description": "Initial recon",
        "steps": [
            {"name": "whoami", "kind": "native", "atck": "T1033", "command": "execute", "args": ["-o", "whoami"]},
            {"name": "systeminfo", "kind": "native", "atck": "T1082", "command": "execute", "args": ["-o", "systeminfo"]},
        ],
    },
    "S2_creds": {
        "description": "Credential theft",
        "steps": [
            {"name": "mimikatz", "kind": "execute_assembly", "atck": "T1003.001", "command": "Mimikatz.exe", "args": ["sekurlsa::logonpasswords"]},
        ],
    },
}


def test_sliver_runner_list_scenarios_returns_attack_scenarios():
    runner = SliverRunner(scenarios=FAKE_SCENARIOS)
    scenarios = runner.list_scenarios()
    assert len(scenarios) == 2
    assert all(isinstance(s, AttackScenario) for s in scenarios)


def test_sliver_runner_scenario_ids_match_keys():
    runner = SliverRunner(scenarios=FAKE_SCENARIOS)
    ids = {s.id for s in runner.list_scenarios()}
    assert ids == {"S1_recon", "S2_creds"}


def test_sliver_runner_extracts_mitre_techniques_from_steps():
    runner = SliverRunner(scenarios=FAKE_SCENARIOS)
    scenarios = {s.id: s for s in runner.list_scenarios()}
    assert "T1033" in scenarios["S1_recon"].mitre_techniques
    assert "T1082" in scenarios["S1_recon"].mitre_techniques
    assert "T1003.001" in scenarios["S2_creds"].mitre_techniques


def test_sliver_runner_run_scenario_raises_when_not_configured():
    runner = SliverRunner(scenarios=FAKE_SCENARIOS)
    scenario = runner.list_scenarios()[0]
    with pytest.raises(RuntimeError, match="SliverRunner"):
        runner.run_scenario(scenario)


def test_sliver_runner_run_scenario_raises_even_with_partial_config():
    runner = SliverRunner(config={"port": 31337}, scenarios=FAKE_SCENARIOS)
    scenario = runner.list_scenarios()[0]
    with pytest.raises(RuntimeError, match="host"):
        runner.run_scenario(scenario)


def test_sliver_runner_empty_scenarios():
    runner = SliverRunner(scenarios={})
    assert runner.list_scenarios() == []
```

- [ ] **Step 2: Run to verify failures**

```python
import subprocess, sys
r = subprocess.run([sys.executable, "-m", "pytest", "tests/attack/test_sliver.py", "-v"], capture_output=True, text=True, cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec")
print(r.stdout, r.stderr)
```

Expected: `ModuleNotFoundError: No module named 'attack.sliver'`

- [ ] **Step 3: Create `attack/sliver.py`**

```python
# attack/sliver.py
"""
SliverRunner — executes Sliver C2 scenarios against a live SIEM.

Requires a configured Sliver C2 server. If not configured, run_scenario()
raises RuntimeError cleanly. Tests inject scenarios via the constructor.
"""
from __future__ import annotations

from attack.base import AttackRunner, AttackScenario, ScenarioResult


class SliverRunner(AttackRunner):
    """
    Attack runner backed by Sliver C2.

    Args:
        config:    Connection config dict. Required key: "host" (Sliver server address).
        scenarios: Optional scenarios dict (same schema as sliver_test_harness/scenarios.py).
                   If None, loads from sliver_test_harness.scenarios.SCENARIOS at runtime.
    """

    def __init__(
        self,
        config: dict | None = None,
        scenarios: dict | None = None,
    ) -> None:
        self._config = config or {}
        self._raw_scenarios = scenarios  # None = load lazily from sliver_test_harness

    def list_scenarios(self) -> list[AttackScenario]:
        """Return all available Sliver scenarios as AttackScenario objects."""
        raw = self._raw_scenarios
        if raw is None:
            from sliver_test_harness.scenarios import SCENARIOS
            raw = SCENARIOS

        result: list[AttackScenario] = []
        for sid, sdata in raw.items():
            techniques = list({
                step["atck"]
                for step in sdata["steps"]
                if "atck" in step
            })
            result.append(
                AttackScenario(
                    id=sid,
                    description=sdata.get("description", sid),
                    mitre_techniques=techniques,
                    steps=sdata["steps"],
                )
            )
        return result

    def run_scenario(self, scenario: AttackScenario) -> ScenarioResult:
        """
        Execute scenario via Sliver C2.

        Raises:
            RuntimeError: if config["host"] is not set (Sliver not configured).
            NotImplementedError: always — live Sliver integration is a future step.
        """
        if not self._config.get("host"):
            raise RuntimeError(
                "SliverRunner: no host configured. Set config['host'] to the Sliver C2 address."
            )
        raise NotImplementedError(
            "SliverRunner.run_scenario() requires a live Sliver C2 connection."
        )
```

- [ ] **Step 4: Run tests to verify they pass**

```python
import subprocess, sys
r = subprocess.run([sys.executable, "-m", "pytest", "tests/attack/test_sliver.py", "-v"], capture_output=True, text=True, cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec")
print(r.stdout, r.stderr)
```

Expected: 6 tests PASS

- [ ] **Step 5: Run full suite**

```python
import subprocess, sys
r = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-q"], capture_output=True, text=True, cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec")
print(r.stdout, r.stderr)
```

Expected: all prior + 6 new = 156 pass

- [ ] **Step 6: Commit**

```python
import subprocess
r = subprocess.run(
    ["git", "add", "attack/sliver.py", "tests/attack/test_sliver.py"],
    cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec", capture_output=True, text=True
)
r2 = subprocess.run(
    ["git", "commit", "-m", "feat: add SliverRunner stub loading sliver_test_harness scenarios\n\nCo-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"],
    cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec", capture_output=True, text=True
)
print(r.stdout, r.stderr, r2.stdout, r2.stderr)
```

---

## Task 3: `attack/atomic.py` — AtomicRunner

**Files:**
- Create: `attack/atomic.py`
- Create: `tests/attack/test_atomic.py`

`AtomicRunner` is a scaffold for Atomic Red Team. Scenarios are registered programmatically via `register_scenario()` (no external file — Atomic test definitions come from invoke-atomicredteam at runtime). Like `SliverRunner`, `run_scenario()` raises `RuntimeError` if unconfigured.

- [ ] **Step 1: Write failing tests**

```python
# tests/attack/test_atomic.py
"""Tests for AtomicRunner."""
import pytest
from attack.base import AttackScenario, ScenarioResult
from attack.atomic import AtomicRunner


def _make_scenario(sid: str = "T1059.001") -> AttackScenario:
    return AttackScenario(
        id=sid,
        description=f"Atomic test {sid}",
        mitre_techniques=[sid],
        steps=[{"name": "exec", "kind": "shell", "command": "powershell.exe", "args": ["-c", "whoami"]}],
    )


def test_atomic_runner_starts_with_no_scenarios():
    runner = AtomicRunner()
    assert runner.list_scenarios() == []


def test_atomic_runner_register_scenario_adds_it():
    runner = AtomicRunner()
    s = _make_scenario("T1059.001")
    runner.register_scenario(s)
    assert len(runner.list_scenarios()) == 1
    assert runner.list_scenarios()[0].id == "T1059.001"


def test_atomic_runner_register_multiple_scenarios():
    runner = AtomicRunner()
    runner.register_scenario(_make_scenario("T1059.001"))
    runner.register_scenario(_make_scenario("T1082"))
    assert len(runner.list_scenarios()) == 2


def test_atomic_runner_run_scenario_raises_when_not_configured():
    runner = AtomicRunner()
    runner.register_scenario(_make_scenario())
    with pytest.raises(RuntimeError, match="AtomicRunner"):
        runner.run_scenario(runner.list_scenarios()[0])


def test_atomic_runner_run_scenario_raises_when_missing_host():
    runner = AtomicRunner(config={"user": "admin"})
    runner.register_scenario(_make_scenario())
    with pytest.raises(RuntimeError, match="host"):
        runner.run_scenario(runner.list_scenarios()[0])


def test_atomic_runner_list_scenarios_returns_copy():
    runner = AtomicRunner()
    runner.register_scenario(_make_scenario())
    result = runner.list_scenarios()
    result.clear()
    # Internal list not mutated
    assert len(runner.list_scenarios()) == 1
```

- [ ] **Step 2: Run to verify failures**

```python
import subprocess, sys
r = subprocess.run([sys.executable, "-m", "pytest", "tests/attack/test_atomic.py", "-v"], capture_output=True, text=True, cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec")
print(r.stdout, r.stderr)
```

Expected: `ModuleNotFoundError: No module named 'attack.atomic'`

- [ ] **Step 3: Create `attack/atomic.py`**

```python
# attack/atomic.py
"""
AtomicRunner — executes Atomic Red Team tests against a live SIEM.

Scenarios are registered programmatically via register_scenario().
Requires invoke-atomicredteam or Atomic API. If not configured,
run_scenario() raises RuntimeError cleanly.
"""
from __future__ import annotations

from attack.base import AttackRunner, AttackScenario, ScenarioResult


class AtomicRunner(AttackRunner):
    """
    Attack runner backed by Atomic Red Team.

    Args:
        config: Connection config dict. Required key: "host" (target host for invoke).
    """

    def __init__(self, config: dict | None = None) -> None:
        self._config = config or {}
        self._scenarios: list[AttackScenario] = []

    def register_scenario(self, scenario: AttackScenario) -> None:
        """Add a scenario to this runner's execution list."""
        self._scenarios.append(scenario)

    def list_scenarios(self) -> list[AttackScenario]:
        """Return a copy of the registered scenario list."""
        return list(self._scenarios)

    def run_scenario(self, scenario: AttackScenario) -> ScenarioResult:
        """
        Execute scenario via Atomic Red Team.

        Raises:
            RuntimeError: if config["host"] is not set.
            NotImplementedError: always — live Atomic integration is a future step.
        """
        if not self._config.get("host"):
            raise RuntimeError(
                "AtomicRunner: no host configured. Set config['host'] to the target host."
            )
        raise NotImplementedError(
            "AtomicRunner.run_scenario() requires invoke-atomicredteam on the target host."
        )
```

- [ ] **Step 4: Run tests to verify they pass**

```python
import subprocess, sys
r = subprocess.run([sys.executable, "-m", "pytest", "tests/attack/test_atomic.py", "-v"], capture_output=True, text=True, cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec")
print(r.stdout, r.stderr)
```

Expected: 6 tests PASS

- [ ] **Step 5: Run full suite**

```python
import subprocess, sys
r = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-q"], capture_output=True, text=True, cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec")
print(r.stdout, r.stderr)
```

Expected: all prior + 6 new = 162 pass

- [ ] **Step 6: Commit**

```python
import subprocess
r = subprocess.run(
    ["git", "add", "attack/atomic.py", "tests/attack/test_atomic.py"],
    cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec", capture_output=True, text=True
)
r2 = subprocess.run(
    ["git", "commit", "-m", "feat: add AtomicRunner scaffold for Atomic Red Team\n\nCo-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"],
    cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec", capture_output=True, text=True
)
print(r.stdout, r.stderr, r2.stdout, r2.stderr)
```

---

## Task 4: `pipeline/attack_chain.py` — orchestrator

**Files:**
- Create: `pipeline/attack_chain.py`
- Create: `tests/pipeline/test_attack_chain.py`

`run_attack_chain()` iterates over all runners × scenarios. When `run_scenario()` raises `RuntimeError` or `NotImplementedError` (runner not configured), the error is recorded in the result's `errors` list and execution continues with the remaining scenarios. All collected alerts are saved via `ResultStore.save_alerts()`.

Returns `AttackChainResult` — a simple dataclass with `alerts: list[dict]`, `run_id: str`, `errors: list[str]`, `scenario_count: int`.

- [ ] **Step 1: Write failing tests**

```python
# tests/pipeline/test_attack_chain.py
"""Tests for run_attack_chain()."""
import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

from attack.base import AttackRunner, AttackScenario, ScenarioResult
from pipeline.attack_chain import AttackChainResult, run_attack_chain
from storage.result_store import ResultStore


def _make_scenario(sid: str = "S1") -> AttackScenario:
    return AttackScenario(
        id=sid,
        description=f"Scenario {sid}",
        mitre_techniques=["T1059.001"],
        steps=[],
    )


def _mock_runner(scenarios: list[AttackScenario], fired_by_scenario: dict[str, list[str]]) -> AttackRunner:
    """Create a mock runner that returns pre-canned ScenarioResults."""
    runner = MagicMock(spec=AttackRunner)
    runner.list_scenarios.return_value = scenarios

    def _run(scenario):
        fired = fired_by_scenario.get(scenario.id, [])
        return ScenarioResult(
            scenario_id=scenario.id,
            mitre_techniques=scenario.mitre_techniques,
            fired_rule_ids=fired,
            raw_alert_count=len(fired),
        )
    runner.run_scenario.side_effect = _run
    return runner


# ---------------------------------------------------------------------------
# AttackChainResult data type
# ---------------------------------------------------------------------------

def test_attack_chain_result_stores_fields():
    r = AttackChainResult(alerts=[{"rule_id": "r1", "scenario_id": "S1"}], run_id="run-1", errors=[], scenario_count=1)
    assert r.run_id == "run-1"
    assert len(r.alerts) == 1
    assert r.errors == []
    assert r.scenario_count == 1


# ---------------------------------------------------------------------------
# run_attack_chain()
# ---------------------------------------------------------------------------

def test_run_attack_chain_collects_alerts(tmp_path):
    store = ResultStore(tmp_path)
    s1 = _make_scenario("S1")
    runner = _mock_runner([s1], {"S1": ["rule-a", "rule-b"]})

    result = run_attack_chain([runner], store, run_id="run-1")

    assert len(result.alerts) == 2
    assert result.scenario_count == 1
    assert result.errors == []


def test_run_attack_chain_saves_alerts_to_store(tmp_path):
    store = ResultStore(tmp_path)
    s1 = _make_scenario("S1")
    runner = _mock_runner([s1], {"S1": ["rule-x"]})

    run_attack_chain([runner], store, run_id="myrun")

    loaded = store.load_alerts("myrun")
    assert len(loaded) == 1
    assert loaded[0]["rule_id"] == "rule-x"
    assert loaded[0]["scenario_id"] == "S1"


def test_run_attack_chain_merges_multiple_runners(tmp_path):
    store = ResultStore(tmp_path)
    s1 = _make_scenario("S1")
    s2 = _make_scenario("S2")
    runner_a = _mock_runner([s1], {"S1": ["rule-1"]})
    runner_b = _mock_runner([s2], {"S2": ["rule-2", "rule-3"]})

    result = run_attack_chain([runner_a, runner_b], store, run_id="r1")

    assert len(result.alerts) == 3
    assert result.scenario_count == 2


def test_run_attack_chain_records_runtime_error_and_continues(tmp_path):
    store = ResultStore(tmp_path)
    s1 = _make_scenario("S1")
    s2 = _make_scenario("S2")

    failing_runner = MagicMock(spec=AttackRunner)
    failing_runner.list_scenarios.return_value = [s1]
    failing_runner.run_scenario.side_effect = RuntimeError("not configured")

    good_runner = _mock_runner([s2], {"S2": ["rule-ok"]})

    result = run_attack_chain([failing_runner, good_runner], store, run_id="r1")

    assert len(result.alerts) == 1
    assert result.alerts[0]["rule_id"] == "rule-ok"
    assert len(result.errors) == 1
    assert "not configured" in result.errors[0]


def test_run_attack_chain_empty_runners_returns_empty(tmp_path):
    store = ResultStore(tmp_path)
    result = run_attack_chain([], store, run_id="empty")
    assert result.alerts == []
    assert result.errors == []
    assert result.scenario_count == 0


def test_run_attack_chain_auto_generates_run_id_when_none(tmp_path):
    store = ResultStore(tmp_path)
    runner = _mock_runner([], {})
    result = run_attack_chain([runner], store)
    assert result.run_id != ""
    assert len(result.run_id) > 0
```

- [ ] **Step 2: Run to verify failures**

```python
import subprocess, sys
r = subprocess.run([sys.executable, "-m", "pytest", "tests/pipeline/test_attack_chain.py", "-v"], capture_output=True, text=True, cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec")
print(r.stdout, r.stderr)
```

Expected: `ModuleNotFoundError: No module named 'pipeline.attack_chain'`

- [ ] **Step 3: Create `pipeline/attack_chain.py`**

```python
# pipeline/attack_chain.py
"""
Orchestrates attack chain runners, collects alerts, and persists results.

Usage:
    from attack.sliver import SliverRunner
    from pipeline.attack_chain import run_attack_chain
    from storage.result_store import ResultStore

    store = ResultStore(Path("output"))
    runner = SliverRunner(config={"host": "sliver.lab.local"})
    result = run_attack_chain([runner], store)
    # result.alerts is compatible with compare_rules(alerts=result.alerts)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from attack.base import AttackRunner, AttackScenario, ScenarioResult
from storage.result_store import ResultStore


@dataclass
class AttackChainResult:
    """Aggregated output from one attack chain run."""
    alerts: list[dict]       # compatible with compare_rules(alerts=...)
    run_id: str
    errors: list[str]        # error messages from failed scenarios
    scenario_count: int      # total scenarios attempted


def run_attack_chain(
    runners: list[AttackRunner],
    store: ResultStore,
    run_id: str | None = None,
) -> AttackChainResult:
    """
    Execute all scenarios from all runners, merge alerts, and save to store.

    If a runner raises RuntimeError or NotImplementedError (not configured),
    the error is recorded and execution continues with the next scenario.

    Args:
        runners:  List of AttackRunner instances (Sliver, Atomic, etc.)
        store:    ResultStore for persisting the collected alerts
        run_id:   Optional stable identifier for this run (auto-generated if None)

    Returns:
        AttackChainResult with aggregated alerts, run_id, errors, and scenario count
    """
    if run_id is None:
        run_id = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    all_alerts: list[dict] = []
    errors: list[str] = []
    scenario_count = 0

    for runner in runners:
        for scenario in runner.list_scenarios():
            scenario_count += 1
            try:
                result: ScenarioResult = runner.run_scenario(scenario)
                all_alerts.extend(result.to_alert_dicts())
            except (RuntimeError, NotImplementedError) as exc:
                errors.append(f"{scenario.id}: {exc}")

    store.save_alerts(run_id, all_alerts)

    return AttackChainResult(
        alerts=all_alerts,
        run_id=run_id,
        errors=errors,
        scenario_count=scenario_count,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

```python
import subprocess, sys
r = subprocess.run([sys.executable, "-m", "pytest", "tests/pipeline/test_attack_chain.py", "-v"], capture_output=True, text=True, cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec")
print(r.stdout, r.stderr)
```

Expected: 7 tests PASS

- [ ] **Step 5: Run full suite**

```python
import subprocess, sys
r = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-q"], capture_output=True, text=True, cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec")
print(r.stdout, r.stderr)
```

Expected: all prior + 7 new = 169 pass

- [ ] **Step 6: Commit**

```python
import subprocess
r = subprocess.run(
    ["git", "add", "pipeline/attack_chain.py", "tests/pipeline/test_attack_chain.py"],
    cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec", capture_output=True, text=True
)
r2 = subprocess.run(
    ["git", "commit", "-m", "feat: add pipeline/attack_chain.py with run_attack_chain()\n\nCo-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"],
    cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec", capture_output=True, text=True
)
print(r.stdout, r.stderr, r2.stdout, r2.stderr)
```

---

## Task 5: Integration tests + merge to main

**Files:**
- Create: `tests/pipeline/test_attack_integration.py`

This wires the full chain: mock runner → `run_attack_chain()` → `ResultStore` → `compare_rules()`. Validates that the alert format produced by `to_alert_dicts()` is correctly consumed by `compare_rules(alerts=...)`.

- [ ] **Step 1: Write integration tests**

```python
# tests/pipeline/test_attack_integration.py
"""
Integration test: mock runner → run_attack_chain → compare_rules round-trip.

Validates that alerts produced by the attack chain flow correctly into
compare_rules() and affect overlap detection as expected.
"""
import pytest
from unittest.mock import MagicMock

from attack.base import AttackRunner, AttackScenario, ScenarioResult
from pipeline.attack_chain import run_attack_chain
from pipeline.compare import compare_rules
from pipeline.decide import decide
from storage.result_store import ResultStore
from core.ast_model import RuleAST


def _make_rule(rule_id: str, catalog: str, translated: str | None = None) -> RuleAST:
    return RuleAST(
        id=rule_id,
        catalog=catalog,
        name=f"Rule {rule_id}",
        description="",
        severity="medium",
        mitre_techniques=[],
        event_categories=[],
        conditions=[],
        raw_query="",
        language="eql",
        translated_query=translated,
        source_path="test",
        metadata={},
    )


def _mock_runner(scenario_id: str, fired_rule_ids: list[str]) -> AttackRunner:
    scenario = AttackScenario(
        id=scenario_id, description="test", mitre_techniques=["T1059"], steps=[]
    )
    result = ScenarioResult(
        scenario_id=scenario_id,
        mitre_techniques=["T1059"],
        fired_rule_ids=fired_rule_ids,
        raw_alert_count=len(fired_rule_ids),
    )
    runner = MagicMock(spec=AttackRunner)
    runner.list_scenarios.return_value = [scenario]
    runner.run_scenario.return_value = result
    return runner


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------

def test_attack_chain_alerts_flow_into_compare_rules(tmp_path):
    """
    Rules with zero logic overlap but co-firing alerts → marked as overlap.
    """
    store = ResultStore(tmp_path)
    # sigma rule s1 and elastic rule e1 have completely different queries
    s1 = _make_rule("s1", "sigma", translated='process where process.name == "cmd.exe"')
    e1 = _make_rule("e1", "elastic", translated='network where destination.port == 4444')

    # Both fire on the same scenario
    runner = _mock_runner("T1059", ["s1", "e1"])
    chain_result = run_attack_chain([runner], store, run_id="run-1")

    compare_result = compare_rules([s1], [e1], alerts=chain_result.alerts, threshold=0.15)
    assert compare_result.confidence == "full"
    assert len(compare_result.overlaps) == 1
    assert compare_result.overlaps[0].alert_confirmed is True
    assert compare_result.unique_a == []  # s1 is covered


def test_attack_chain_non_co_firing_rules_stay_unique(tmp_path):
    """
    Rules where each fires in a different scenario → no alert overlap → stays unique.
    """
    store = ResultStore(tmp_path)
    s1 = _make_rule("s1", "sigma", translated='process where process.name == "cmd.exe"')
    e1 = _make_rule("e1", "elastic", translated='network where destination.port == 4444')

    # Each fires in a different scenario
    runner_a = _mock_runner("T1059", ["s1"])
    runner_b = _mock_runner("T1082", ["e1"])

    chain_result = run_attack_chain([runner_a, runner_b], store, run_id="run-2")

    compare_result = compare_rules([s1], [e1], alerts=chain_result.alerts, threshold=0.15)
    assert len(compare_result.overlaps) == 0
    assert len(compare_result.unique_a) == 1  # s1 is unique → should be ADDed


def test_full_chain_decide_from_attack_alerts(tmp_path):
    """
    Full pipeline: attack_chain → compare_rules → decide → correct ADD/SKIP decisions.
    """
    store = ResultStore(tmp_path)
    s1 = _make_rule("s1", "sigma", translated='process where process.name == "cmd.exe"')
    s2 = _make_rule("s2", "sigma", translated='file where file.name == "malware.exe"')
    e1 = _make_rule("e1", "elastic", translated='network where destination.port == 4444')

    # s1 and e1 co-fire → s1 should SKIP; s2 doesn't fire → s2 should ADD
    runner = _mock_runner("T1059", ["s1", "e1"])
    chain_result = run_attack_chain([runner], store, run_id="run-3")

    compare_result = compare_rules([s1, s2], [e1], alerts=chain_result.alerts, threshold=0.15)
    decisions = decide(compare_result)

    assert decisions["s1"] == "SKIP"
    assert decisions["s2"] == "ADD"
```

- [ ] **Step 2: Run integration tests**

```python
import subprocess, sys
r = subprocess.run([sys.executable, "-m", "pytest", "tests/pipeline/test_attack_integration.py", "-v"], capture_output=True, text=True, cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec")
print(r.stdout, r.stderr)
```

Expected: 3 tests PASS

- [ ] **Step 3: Run full test suite and record count**

```python
import subprocess, sys
r = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-q"], capture_output=True, text=True, cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec")
print(r.stdout, r.stderr)
```

Expected: all tests pass (≈ 172 total)

- [ ] **Step 4: Commit integration tests**

```python
import subprocess
r = subprocess.run(
    ["git", "add", "tests/pipeline/test_attack_integration.py"],
    cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec", capture_output=True, text=True
)
r2 = subprocess.run(
    ["git", "commit", "-m", "test: add attack chain integration tests (mock runner → compare_rules)\n\nCo-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"],
    cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec", capture_output=True, text=True
)
print(r.stdout, r.stderr, r2.stdout, r2.stderr)
```

- [ ] **Step 5: Merge to main**

```python
import subprocess
cwd = r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec"

r1 = subprocess.run(["git", "checkout", "main"], cwd=cwd, capture_output=True, text=True)
print(r1.stdout, r1.stderr)

r2 = subprocess.run(
    ["git", "merge", "--no-ff", "plan4-attack", "-m",
     "feat: Plan 4 — attack chain (AttackRunner, SliverRunner, AtomicRunner, run_attack_chain)\n\nCo-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"],
    cwd=cwd, capture_output=True, text=True
)
print(r2.stdout, r2.stderr)

r3 = subprocess.run(["git", "branch", "-d", "plan4-attack"], cwd=cwd, capture_output=True, text=True)
print(r3.stdout, r3.stderr)
```

- [ ] **Step 6: Verify on main**

```python
import subprocess, sys
r = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-q"], capture_output=True, text=True, cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec")
print(r.stdout, r.stderr)
```

Expected: all tests pass on main

---

## Self-Review Notes

**Spec coverage:**
- ✅ `attack/base.py` — `AttackRunner` ABC, `AttackScenario`, `ScenarioResult` (spec §Attack Chain Integration)
- ✅ `attack/sliver.py` — `SliverRunner` wrapping `sliver_test_harness/scenarios.py` (spec §attack/sliver.py)
- ✅ `attack/atomic.py` — `AtomicRunner` scaffold (spec §attack/atomic.py)
- ✅ `pipeline/attack_chain.py` — orchestrates runners, writes `output/alerts/` (spec §pipeline/attack_chain.py)
- ✅ Alert format `{"rule_id": ..., "scenario_id": ...}` — compatible with `compare_rules(alerts=...)` (spec §Comparison Logic)
- ✅ Logic-only fallback: if attack chain raises, errors captured but pipeline continues (spec §Fallback)
- ✅ `ResultStore.save_alerts()` / `load_alerts()` already implemented in Plan 3 — used here as-is

**Type consistency:**
- `ScenarioResult.to_alert_dicts()` → `[{"rule_id": ..., "scenario_id": ...}]` matches keys read by `compare_rules()` (`alert.get("rule_id")`, `alert.get("scenario_id")`)
- `AttackChainResult.alerts` is the same list passed directly to `compare_rules(alerts=...)`
- `run_attack_chain()` parameter order: `(runners, store, run_id)` — store before run_id for consistency with Python convention (required params first)

**Placeholder scan:** None. All steps contain complete code.
