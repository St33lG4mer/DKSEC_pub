# DKSec Refactor — Plan 6: CLI + UI

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Wire the pipeline into a Click-based CLI (`cli.py`) and build a catalog-agnostic Streamlit UI under `ui/`. The CLI enables headless automation; the UI enables interactive visualization at `dksec.kaspergissel.dk`.

**Architecture:**
- `cli.py` — Click entry point with 7 commands: `ingest`, `translate`, `compare`, `decide`, `attack`, `deploy`, `run-all`. Each command instantiates the correct adapter (via catalog name) and calls the matching pipeline step. Reads catalog/output paths and SIEM credentials from `config.yaml`.
- `ui/dashboard.py` — New Streamlit entry point. Reads `catalogs/` via `RuleStore` and `output/` via `ResultStore`. No hardcoded catalog names — uses `store.list_catalogs()` for dynamic pickers.
- `ui/pages/` — 6 pages replacing the old `pages/` folder.

**Old files kept as-is** (not deleted in this plan — will be cleaned up in Plan 7 once the new UI is verified working):
- `dashboard.py`, `pages/`, `utils.py` — still importable for reference.

**Tech Stack:** Python 3.10+, `click>=8.0`, `streamlit>=1.35`, `pytest`, `click.testing.CliRunner`

---

## Pre-requisite

```
git checkout main
git pull
git checkout -b plan6-cli-ui
```

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `cli.py` | Create | Click CLI — 7 commands |
| `ui/__init__.py` | Create | Package marker |
| `ui/dashboard.py` | Create | Streamlit entry point (catalog-agnostic) |
| `ui/pages/__init__.py` | Create | Package marker |
| `ui/pages/home.py` | Create | Overview: catalog picker, pipeline metrics |
| `ui/pages/comparison.py` | Create | Overlap/unique analysis — catalog picker |
| `ui/pages/catalogs.py` | Create | Browse rules from any loaded catalog |
| `ui/pages/attack_chain.py` | Create | Attack run history, alert counts |
| `ui/pages/deploy_preview.py` | Create | Review unique rules, launch deploy |
| `ui/pages/scoring.py` | Create | Rule scoring & prioritization |
| `tests/test_cli.py` | Create | 8 CLI tests using CliRunner |

---

## Shared context helpers

```python
# In tests/test_cli.py — used across CLI tests
from click.testing import CliRunner
from cli import cli

def invoke(*args, **env):
    runner = CliRunner(mix_stderr=False)
    return runner.invoke(cli, list(args), catch_exceptions=False)
```

---

## Task 1: `cli.py` + `tests/test_cli.py`

**Files:**
- Create: `cli.py`
- Create: `tests/test_cli.py`

### Step 1: Write failing tests

```python
# tests/test_cli.py
"""Tests for the DKSec CLI (cli.py)."""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from cli import cli


def _runner():
    return CliRunner(mix_stderr=False)


def test_cli_help_shows_commands():
    result = _runner().invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "ingest" in result.output
    assert "translate" in result.output
    assert "compare" in result.output
    assert "decide" in result.output
    assert "deploy" in result.output


def test_ingest_command_calls_ingest_catalog(tmp_path):
    sigma_dir = tmp_path / "sigma"
    sigma_dir.mkdir()

    with patch("cli.ingest_catalog") as mock_ingest, \
         patch("cli.SigmaAdapter") as mock_adapter_cls, \
         patch("cli.RuleStore") as mock_store_cls:
        mock_ingest.return_value = MagicMock(catalog="sigma", raw_count=5, failed_count=0, errors=[])
        result = _runner().invoke(cli, [
            "ingest", "--catalog", "sigma", "--source", "folder", "--path", str(sigma_dir)
        ])

    assert result.exit_code == 0
    assert "5" in result.output  # raw_count in output


def test_translate_command_calls_translate_catalog(tmp_path):
    with patch("cli.translate_catalog") as mock_translate, \
         patch("cli.SigmaAdapter") as mock_adapter_cls, \
         patch("cli.RuleStore") as mock_store_cls:
        mock_translate.return_value = MagicMock(catalog="sigma", translated_count=3, failed_count=0, errors=[])
        result = _runner().invoke(cli, ["translate", "--catalog", "sigma"])

    assert result.exit_code == 0
    assert "3" in result.output


def test_compare_command_calls_compare_rules(tmp_path):
    from core.ast_model import RuleAST
    from pipeline.compare import CompareResult

    with patch("cli.RuleStore") as mock_store_cls, \
         patch("cli.ResultStore") as mock_result_store_cls, \
         patch("cli.compare_rules") as mock_compare:
        mock_store = MagicMock()
        mock_store.load_all.return_value = []
        mock_store_cls.return_value = mock_store
        mock_compare.return_value = CompareResult(
            overlaps=[], unique_a=[], unique_b=[],
            confidence="logic-only", catalog_a="sigma", catalog_b="elastic"
        )
        result = _runner().invoke(cli, ["compare", "--a", "sigma", "--b", "elastic"])

    assert result.exit_code == 0
    assert "logic-only" in result.output


def test_decide_command_calls_decide(tmp_path):
    from pipeline.compare import CompareResult
    from pipeline.decide import decide

    with patch("cli.RuleStore") as mock_store_cls, \
         patch("cli.ResultStore") as mock_result_store_cls, \
         patch("cli.compare_rules") as mock_compare, \
         patch("cli.decide") as mock_decide:
        mock_store = MagicMock()
        mock_store.load_all.return_value = []
        mock_store_cls.return_value = mock_store
        mock_compare.return_value = MagicMock(unique_a=[], overlaps=[], confidence="logic-only", catalog_a="sigma", catalog_b="elastic")
        mock_decide.return_value = {"rule-1": "ADD", "rule-2": "SKIP"}
        result = _runner().invoke(cli, ["decide", "--a", "sigma", "--b", "elastic"])

    assert result.exit_code == 0
    assert "ADD" in result.output or "SKIP" in result.output or "decisions" in result.output.lower()


def test_deploy_test_mode_requires_catalog_and_target():
    result = _runner().invoke(cli, ["deploy", "--mode", "test"])
    # Missing required options should fail
    assert result.exit_code != 0


def test_run_all_skip_attack_flag(tmp_path):
    from pipeline.compare import CompareResult

    with patch("cli.RuleStore") as mock_store_cls, \
         patch("cli.ResultStore") as mock_result_store_cls, \
         patch("cli.ingest_catalog") as mock_ingest, \
         patch("cli.translate_catalog") as mock_translate, \
         patch("cli.compare_rules") as mock_compare, \
         patch("cli.decide") as mock_decide:
        mock_store = MagicMock()
        mock_store.load_all.return_value = []
        mock_store_cls.return_value = mock_store
        mock_ingest.return_value = MagicMock(catalog="sigma", raw_count=0, failed_count=0, errors=[])
        mock_translate.return_value = MagicMock(catalog="sigma", translated_count=0, failed_count=0, errors=[])
        mock_compare.return_value = CompareResult(
            overlaps=[], unique_a=[], unique_b=[],
            confidence="logic-only", catalog_a="sigma", catalog_b="elastic"
        )
        mock_decide.return_value = {}
        result = _runner().invoke(cli, [
            "run-all", "--a", "sigma", "--b", "elastic", "--skip-attack"
        ])

    assert result.exit_code == 0


def test_attack_command_requires_framework():
    result = _runner().invoke(cli, ["attack"])
    assert result.exit_code != 0
```

### Step 2: Verify tests fail (ImportError on cli)

### Step 3: Create `cli.py`

```python
# cli.py
"""
DKSec CLI — catalog-agnostic detection rule comparison pipeline.

Usage examples:
    dksec ingest --catalog sigma --source folder --path ./sigma-rules
    dksec translate --catalog sigma
    dksec compare --a sigma --b elastic
    dksec decide --a sigma --b elastic
    dksec attack --framework sliver
    dksec deploy --mode test --catalog sigma --target elastic
    dksec run-all --a sigma --b elastic --skip-attack
"""
from __future__ import annotations

import sys
from pathlib import Path

import click

from pipeline.compare import compare_rules
from pipeline.decide import decide
from pipeline.deploy import deploy_rules
from pipeline.ingest import ingest_catalog
from pipeline.translate import translate_catalog
from storage.result_store import ResultStore
from storage.rule_store import RuleStore

# Default paths — override via env or future config integration
_CATALOGS_DIR = Path("catalogs")
_OUTPUT_DIR = Path("output")


def _rule_store() -> RuleStore:
    return RuleStore(_CATALOGS_DIR)


def _result_store() -> ResultStore:
    return ResultStore(_OUTPUT_DIR)


def _make_sigma_adapter(source: str, path: str | None, url: str | None):
    from adapters.sigma.adapter import SigmaAdapter
    folder = Path(path) if path else _CATALOGS_DIR / "sigma" / "raw"
    return SigmaAdapter(folder_path=folder)


def _make_elastic_adapter(source: str, url: str | None, config: str | None):
    from adapters.elastic.adapter import ElasticAdapter
    return ElasticAdapter()


def _make_adapter(catalog: str, source: str, path: str | None, url: str | None, config: str | None = None):
    if catalog == "sigma":
        return _make_sigma_adapter(source, path, url)
    if catalog == "elastic":
        return _make_elastic_adapter(source, url, config)
    raise click.BadParameter(f"Unknown catalog: {catalog!r}. Supported: sigma, elastic")


@click.group()
def cli():
    """DKSec — catalog-agnostic detection rule comparison pipeline."""


@cli.command()
@click.option("--catalog", required=True, help="Catalog name: sigma, elastic")
@click.option(
    "--source", required=True,
    type=click.Choice(["folder", "git", "api"]),
    help="Source type for the catalog",
)
@click.option("--path", default=None, help="Local folder path (for --source folder)")
@click.option("--url", default=None, help="Git URL or API base URL")
@click.option("--config", default="config.yaml", help="Config file path")
def ingest(catalog: str, source: str, path: str | None, url: str | None, config: str):
    """Step 1: Load raw rules from source and persist for translate step."""
    adapter = _make_adapter(catalog, source, path, url, config)
    store = _rule_store()
    result = ingest_catalog(adapter, store)
    if result.errors:
        click.echo(f"[ERROR] Ingest failed: {result.errors[0]}", err=True)
        sys.exit(1)
    click.echo(f"✅  Ingested {result.raw_count} raw rules from catalog '{result.catalog}'")


@cli.command()
@click.option("--catalog", required=True, help="Catalog name: sigma, elastic")
@click.option("--source", default="folder", type=click.Choice(["folder", "git", "api"]))
@click.option("--path", default=None)
def translate(catalog: str, source: str, path: str | None):
    """Step 2: Parse and translate raw rules to canonical RuleAST."""
    adapter = _make_adapter(catalog, source, path, url=None)
    store = _rule_store()
    result = translate_catalog(adapter, store)
    status = "⚠️" if result.failed_count else "✅"
    click.echo(
        f"{status}  Translated {result.translated_count} rules "
        f"({result.failed_count} failed) for catalog '{result.catalog}'"
    )
    for err in result.errors[:5]:
        click.echo(f"   ↳ {err}", err=True)


@cli.command()
@click.option("--a", "catalog_a", required=True, help="First catalog (source)")
@click.option("--b", "catalog_b", required=True, help="Second catalog (target SIEM)")
@click.option("--threshold", default=0.15, show_default=True, help="Jaccard similarity threshold")
@click.option("--run-id", default=None, help="Attack chain run ID to include alert data")
def compare(catalog_a: str, catalog_b: str, threshold: float, run_id: str | None):
    """Step 3: Compare two catalogs; report overlaps and unique rules."""
    store = _rule_store()
    result_store = _result_store()

    rules_a = store.load_all(catalog_a)
    rules_b = store.load_all(catalog_b)

    alerts = result_store.load_alerts(run_id) if run_id else None

    result = compare_rules(rules_a, rules_b, alerts=alerts, threshold=threshold)

    overlaps_dicts, unique_dicts = result.to_storage_dicts()
    result_store.save_overlaps(catalog_a, catalog_b, overlaps_dicts)
    result_store.save_unique(catalog_a, catalog_b, unique_dicts)

    click.echo(
        f"✅  Comparison complete [{result.confidence}]  "
        f"Overlaps: {len(result.overlaps)}  "
        f"Unique-A: {len(result.unique_a)}  "
        f"Unique-B: {len(result.unique_b)}"
    )


@cli.command()
@click.option("--a", "catalog_a", required=True)
@click.option("--b", "catalog_b", required=True)
def decide(catalog_a: str, catalog_b: str):
    """Step 4: Generate ADD/SKIP decisions for catalog A rules."""
    store = _rule_store()
    result_store = _result_store()

    rules_a = store.load_all(catalog_a)
    rules_b = store.load_all(catalog_b)
    result = compare_rules(rules_a, rules_b)
    decisions = decide(result)

    result_store.save_decisions(catalog_a, catalog_b, decisions)

    add_count = sum(1 for v in decisions.values() if v == "ADD")
    skip_count = sum(1 for v in decisions.values() if v == "SKIP")
    click.echo(f"✅  Decisions saved — ADD: {add_count}  SKIP: {skip_count}")


@cli.command()
@click.option(
    "--framework", required=True,
    type=click.Choice(["sliver", "atomic", "both"]),
    help="Attack framework to use",
)
@click.option("--run-id", default=None, help="Optional stable run identifier")
def attack(framework: str, run_id: str | None):
    """Step 5: Run MITRE ATT&CK scenarios to generate empirical alert data."""
    from pipeline.attack_chain import run_attack_chain
    from attack.sliver import SliverRunner
    from attack.atomic import AtomicRunner

    result_store = _result_store()
    runners = []

    if framework in ("sliver", "both"):
        runners.append(SliverRunner())
    if framework in ("atomic", "both"):
        runners.append(AtomicRunner())

    chain_result = run_attack_chain(runners, result_store, run_id=run_id)

    status = "⚠️" if chain_result.errors else "✅"
    click.echo(
        f"{status}  Attack chain complete — "
        f"Scenarios: {chain_result.scenario_count}  "
        f"Alerts: {len(chain_result.alerts)}  "
        f"Errors: {len(chain_result.errors)}  "
        f"Run ID: {chain_result.run_id}"
    )
    for err in chain_result.errors[:5]:
        click.echo(f"   ↳ {err}", err=True)


@cli.command()
@click.option(
    "--mode", required=True,
    type=click.Choice(["test", "permanent"]),
    help="'test' = tagged temporary deploy; 'permanent' = persist unique rules",
)
@click.option("--catalog", required=True, help="Catalog to deploy")
@click.option("--target", required=True, help="Target SIEM (e.g. elastic)")
@click.option("--dry-run", is_flag=True, default=False, help="Print rules without deploying")
def deploy(mode: str, catalog: str, target: str, dry_run: bool):
    """Step 3 (test) / Step 6 (permanent): Deploy rules to SIEM."""
    store = _rule_store()
    result_store = _result_store()
    rules = store.load_all(catalog)

    if dry_run:
        click.echo(f"🔍  Dry-run: would deploy {len(rules)} rules from '{catalog}' → '{target}' [{mode}]")
        return

    adapter = _make_adapter(target, "api", path=None, url=None)
    result = deploy_rules(adapter, rules, client=None, mode=mode)

    status = "⚠️" if result.failed_count else "✅"
    click.echo(
        f"{status}  Deployed {result.deployed_count} rules "
        f"({result.failed_count} failed) [{mode}] → {target}"
    )
    for err in result.errors[:5]:
        click.echo(f"   ↳ {err}", err=True)


@cli.command("run-all")
@click.option("--a", "catalog_a", required=True, help="Source catalog (e.g. sigma)")
@click.option("--b", "catalog_b", required=True, help="SIEM catalog (e.g. elastic)")
@click.option("--skip-attack", is_flag=True, default=False, help="Skip attack chain (logic-only mode)")
@click.option("--continue-on-error", is_flag=True, default=False)
def run_all(catalog_a: str, catalog_b: str, skip_attack: bool, continue_on_error: bool):
    """Run the full pipeline end-to-end: ingest → translate → compare → decide."""
    store = _rule_store()
    result_store = _result_store()

    click.echo(f"🚀  Running pipeline: {catalog_a} vs {catalog_b}")

    # --- Ingest ---
    for cat in (catalog_a, catalog_b):
        adapter = _make_adapter(cat, "folder", path=None, url=None)
        ingest_result = ingest_catalog(adapter, store)
        click.echo(f"   Ingest '{cat}': {ingest_result.raw_count} rules")

    # --- Translate ---
    for cat in (catalog_a, catalog_b):
        adapter = _make_adapter(cat, "folder", path=None, url=None)
        translate_result = translate_catalog(adapter, store)
        click.echo(f"   Translate '{cat}': {translate_result.translated_count} rules ({translate_result.failed_count} failed)")

    # --- Attack chain (optional) ---
    alerts = None
    if not skip_attack:
        from pipeline.attack_chain import run_attack_chain
        from attack.sliver import SliverRunner
        chain = run_attack_chain([SliverRunner()], result_store)
        alerts = chain.alerts
        click.echo(f"   Attack chain: {len(alerts)} alerts from {chain.scenario_count} scenarios")
    else:
        click.echo("   ⚠️  Skipping attack chain (--skip-attack); using logic-only comparison")

    # --- Compare ---
    rules_a = store.load_all(catalog_a)
    rules_b = store.load_all(catalog_b)
    compare_result = compare_rules(rules_a, rules_b, alerts=alerts)
    overlaps_dicts, unique_dicts = compare_result.to_storage_dicts()
    result_store.save_overlaps(catalog_a, catalog_b, overlaps_dicts)
    result_store.save_unique(catalog_a, catalog_b, unique_dicts)
    click.echo(
        f"   Compare [{compare_result.confidence}]: "
        f"{len(compare_result.overlaps)} overlaps, {len(compare_result.unique_a)} unique-{catalog_a}"
    )

    # --- Decide ---
    decisions = decide(compare_result)
    result_store.save_decisions(catalog_a, catalog_b, decisions)
    add_count = sum(1 for v in decisions.values() if v == "ADD")
    click.echo(f"   Decide: {add_count} rules marked ADD")

    click.echo(f"✅  Pipeline complete. Results in output/")


if __name__ == "__main__":
    cli()
```

**IMPORTANT NOTE about the `decide` command:** There is a name conflict — Click command named `decide` shadows the imported `decide` function. Fix by importing the pipeline function under an alias:

```python
from pipeline.decide import decide as _decide_pipeline
```

And in the `decide` Click command body, call `_decide_pipeline(result)` instead of `decide(result)`. Same for `run_all` — use `_decide_pipeline`.

### Step 4: Run tests — expect 8 passing
```python
import subprocess, sys
r = subprocess.run([sys.executable, "-m", "pytest", "tests/test_cli.py", "-v", "--tb=short"], capture_output=True, text=True, cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec")
print(r.stdout, r.stderr)
```

### Step 5: Full suite — expect 205 passing (197 + 8)
```python
import subprocess, sys
r = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-q"], capture_output=True, text=True, cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec")
print(r.stdout, r.stderr)
```

### Step 6: Commit
```
git add cli.py tests/test_cli.py
git commit -m "feat: add cli.py Click entry point with 7 pipeline commands

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Task 2: `ui/` package + `ui/dashboard.py`

**Files:**
- Create: `ui/__init__.py`
- Create: `ui/pages/__init__.py`
- Create: `ui/dashboard.py`

No unit tests for Streamlit entry points — they are verified by import (no crash on import).

### `ui/dashboard.py`

```python
# ui/dashboard.py
"""
DKSec UI — catalog-agnostic Streamlit dashboard.

Run with:
    python -m streamlit run ui/dashboard.py
"""
import sys
from pathlib import Path

# Allow imports from project root when launched via streamlit directly
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st

from core.theme import apply_theme
from storage.result_store import ResultStore
from storage.rule_store import RuleStore

_CATALOGS_DIR = Path("catalogs")
_OUTPUT_DIR = Path("output")

st.set_page_config(
    page_title="DKSec",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)
apply_theme()

with st.sidebar:
    st.markdown(
        '<div style="font-size:1.25rem;font-weight:700;color:#e6edf3;padding:4px 0 12px">DKSec</div>',
        unsafe_allow_html=True,
    )

    store = RuleStore(_CATALOGS_DIR)
    result_store = ResultStore(_OUTPUT_DIR)

    catalogs = store.list_catalogs()
    if catalogs:
        st.caption(f"📂 Catalogs loaded: {', '.join(catalogs)}")
    else:
        st.caption("📁 No catalogs loaded — run `dksec ingest` first")

    runs = result_store.list_alert_runs()
    if runs:
        st.caption(f"⚔️ Attack runs: {len(runs)}")

    st.divider()

pg = st.navigation(
    {
        "Analysis": [
            st.Page("ui/pages/comparison.py", title="Comparison",     icon="📊", default=True),
            st.Page("ui/pages/home.py",        title="Overview",       icon="🏠"),
            st.Page("ui/pages/scoring.py",     title="Scoring",        icon="🏆"),
        ],
        "Catalogs": [
            st.Page("ui/pages/catalogs.py",    title="Browse Rules",   icon="📋"),
        ],
        "Operations": [
            st.Page("ui/pages/attack_chain.py",   title="Attack Chain",    icon="⚔️"),
            st.Page("ui/pages/deploy_preview.py", title="Deploy Preview",  icon="🚀"),
        ],
    }
)
pg.run()
```

Note: `apply_theme()` must be added to `core/theme.py`. Check if it exists; if not, add it as a simple function that calls `st.markdown(THEME_CSS, unsafe_allow_html=True)`.

### Step: Verify `core/theme.py` has `apply_theme()`

Read `core/theme.py`. If it does not have `apply_theme()`, append:
```python
def apply_theme() -> None:
    """Inject GitHub Dark CSS into the active Streamlit app."""
    import streamlit as st
    st.markdown(THEME_CSS, unsafe_allow_html=True)
```

### Commit
```
git add ui/__init__.py ui/pages/__init__.py ui/dashboard.py core/theme.py
git commit -m "feat: add ui/ package and catalog-agnostic dashboard entry point

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Task 3: `ui/pages/home.py`, `ui/pages/comparison.py`, `ui/pages/catalogs.py`

**Files:**
- Create: `ui/pages/home.py`
- Create: `ui/pages/comparison.py`
- Create: `ui/pages/catalogs.py`

All three pages read from `RuleStore` and `ResultStore` — no hardcoded catalog names.

### `ui/pages/home.py`

```python
# ui/pages/home.py
"""
Overview page — headline metrics for all loaded catalogs.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import streamlit as st

from core.theme import apply_theme, metric_card_html
from storage.result_store import ResultStore
from storage.rule_store import RuleStore

_CATALOGS_DIR = Path("catalogs")
_OUTPUT_DIR = Path("output")

apply_theme()
st.title("🏠 Overview")

store = RuleStore(_CATALOGS_DIR)
result_store = ResultStore(_OUTPUT_DIR)

catalogs = store.list_catalogs()
if not catalogs:
    st.info("No catalogs loaded yet. Run `dksec ingest --catalog sigma --source folder --path ./rules` to get started.")
    st.stop()

st.caption(f"Loaded catalogs: **{', '.join(catalogs)}**")

# Metrics per catalog
cols = st.columns(len(catalogs))
for i, cat in enumerate(catalogs):
    rules = store.load_all(cat)
    with cols[i]:
        st.metric(f"📂 {cat.title()}", f"{len(rules):,}", "rules loaded")

st.divider()

# Comparison results (if any)
if len(catalogs) >= 2:
    st.markdown("### Comparison Results")
    catalog_a = catalogs[0]
    catalog_b = catalogs[1]
    unique = result_store.load_unique(catalog_a, catalog_b)
    overlaps = result_store.load_overlaps(catalog_a, catalog_b)
    decisions = result_store.load_decisions(catalog_a, catalog_b)

    if decisions:
        add_count = sum(1 for v in decisions.values() if v == "ADD")
        st.success(f"🎯 **{add_count} rules from '{catalog_a}' should be added** to '{catalog_b}'")
        col1, col2 = st.columns(2)
        col1.metric("Overlaps", len(overlaps))
        col2.metric("Unique (to add)", add_count)
    else:
        st.info("No comparison results yet. Run `dksec compare` or `dksec run-all` to generate them.")

st.divider()

# Attack runs
runs = result_store.list_alert_runs()
if runs:
    st.markdown(f"### Attack Runs: {len(runs)}")
    st.caption(f"Latest: {runs[-1]}")
else:
    st.caption("No attack runs yet.")
```

### `ui/pages/comparison.py`

```python
# ui/pages/comparison.py
"""
Comparison page — catalog picker + overlap/unique analysis.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
import streamlit as st

from core.theme import apply_theme
from pipeline.compare import compare_rules
from storage.result_store import ResultStore
from storage.rule_store import RuleStore

_CATALOGS_DIR = Path("catalogs")
_OUTPUT_DIR = Path("output")

apply_theme()
st.title("📊 Comparison")

store = RuleStore(_CATALOGS_DIR)
result_store = ResultStore(_OUTPUT_DIR)
catalogs = store.list_catalogs()

if len(catalogs) < 2:
    st.warning("Need at least 2 catalogs loaded. Run `dksec ingest` for each catalog first.")
    st.stop()

with st.sidebar:
    st.markdown("**Comparison settings**")
    catalog_a = st.selectbox("Catalog A (source)", catalogs, index=0)
    catalog_b = st.selectbox("Catalog B (target)", catalogs, index=min(1, len(catalogs)-1))
    threshold = st.slider("Jaccard threshold", 0.05, 0.80, 0.15, 0.05)
    run_id = None
    runs = result_store.list_alert_runs()
    if runs:
        use_alerts = st.checkbox("Include alert data", value=True)
        if use_alerts:
            run_id = st.selectbox("Attack run", runs, index=len(runs)-1)

if catalog_a == catalog_b:
    st.error("Select two different catalogs.")
    st.stop()

rules_a = store.load_all(catalog_a)
rules_b = store.load_all(catalog_b)

if not rules_a or not rules_b:
    st.warning("One or both catalogs are empty.")
    st.stop()

alerts = result_store.load_alerts(run_id) if run_id else None

with st.spinner("Analysing coverage…"):
    result = compare_rules(rules_a, rules_b, alerts=alerts, threshold=threshold)

# Save results
overlaps_dicts, unique_dicts = result.to_storage_dicts()
result_store.save_overlaps(catalog_a, catalog_b, overlaps_dicts)
result_store.save_unique(catalog_a, catalog_b, unique_dicts)

# Summary metrics
c1, c2, c3, c4 = st.columns(4)
c1.metric(f"{catalog_a.title()} rules", len(rules_a))
c2.metric(f"{catalog_b.title()} rules", len(rules_b))
c3.metric("Overlaps", len(result.overlaps))
c4.metric(f"Unique {catalog_a} (ADD)", len(result.unique_a))

st.caption(f"Confidence: **{result.confidence}**")
st.divider()

# Unique rules table (the primary output)
st.markdown(f"### {catalog_a.title()} Rules to Add ({len(result.unique_a)})")
if result.unique_a:
    rows = [
        {
            "ID": r.id,
            "Name": r.name,
            "Severity": r.severity,
            "MITRE": ", ".join(r.mitre_techniques[:3]),
            "Categories": ", ".join(r.event_categories[:2]),
        }
        for r in result.unique_a
    ]
    sev_filter = st.multiselect("Filter by severity", ["critical","high","medium","low"], default=["critical","high"])
    df = pd.DataFrame(rows)
    if sev_filter:
        df = df[df["Severity"].isin(sev_filter)]
    st.dataframe(df, use_container_width=True, hide_index=True)
else:
    st.success(f"All {catalog_a} rules are already covered by {catalog_b}.")

st.divider()

# Overlaps table
with st.expander(f"Overlap pairs ({len(result.overlaps)})"):
    if result.overlaps:
        overlap_rows = [
            {
                f"{catalog_a} rule": p.rule_a.name,
                f"{catalog_b} rule": p.rule_b.name,
                "Jaccard": round(p.jaccard_score, 3),
                "Alert confirmed": "✅" if p.alert_confirmed else "—",
            }
            for p in result.overlaps
        ]
        st.dataframe(pd.DataFrame(overlap_rows), use_container_width=True, hide_index=True)
```

### `ui/pages/catalogs.py`

```python
# ui/pages/catalogs.py
"""
Catalogs page — browse rules from any loaded catalog.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
import streamlit as st

from core.theme import apply_theme
from storage.rule_store import RuleStore

_CATALOGS_DIR = Path("catalogs")

apply_theme()
st.title("📋 Browse Rules")

store = RuleStore(_CATALOGS_DIR)
catalogs = store.list_catalogs()

if not catalogs:
    st.info("No catalogs loaded yet.")
    st.stop()

with st.sidebar:
    catalog = st.selectbox("Catalog", catalogs)
    sev_filter = st.multiselect("Severity", ["critical", "high", "medium", "low"])
    search = st.text_input("Search rule name")

rules = store.load_all(catalog)
if sev_filter:
    rules = [r for r in rules if r.severity in sev_filter]
if search:
    rules = [r for r in rules if search.lower() in r.name.lower()]

st.caption(f"Showing **{len(rules)}** rules from **{catalog}**")

if rules:
    rows = [
        {
            "ID": r.id[:8] + "…",
            "Name": r.name,
            "Severity": r.severity,
            "Language": r.language,
            "MITRE": ", ".join(r.mitre_techniques[:3]),
            "Translated": "✅" if r.translated_query else "—",
        }
        for r in rules
    ]
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    selected_name = st.selectbox("View rule detail", [r.name for r in rules])
    selected = next(r for r in rules if r.name == selected_name)
    with st.expander("Rule details", expanded=True):
        st.json(selected.to_dict())
```

### Commit
```
git add ui/pages/home.py ui/pages/comparison.py ui/pages/catalogs.py
git commit -m "feat: add ui/pages/home.py, comparison.py, catalogs.py

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Task 4: `ui/pages/attack_chain.py`, `ui/pages/deploy_preview.py`, `ui/pages/scoring.py` + merge

**Files:**
- Create: `ui/pages/attack_chain.py`
- Create: `ui/pages/deploy_preview.py`
- Create: `ui/pages/scoring.py`

### `ui/pages/attack_chain.py`

```python
# ui/pages/attack_chain.py
"""
Attack Chain page — view attack run history and alert data.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
import streamlit as st

from core.theme import apply_theme
from storage.result_store import ResultStore

_OUTPUT_DIR = Path("output")

apply_theme()
st.title("⚔️ Attack Chain")

result_store = ResultStore(_OUTPUT_DIR)
runs = result_store.list_alert_runs()

if not runs:
    st.info(
        "No attack runs yet.  \n"
        "Run `dksec attack --framework sliver` or `dksec run-all` to execute MITRE ATT&CK scenarios."
    )
    st.stop()

st.caption(f"**{len(runs)} run(s)** found in output/alerts/")

selected_run = st.selectbox("Select run", runs, index=len(runs)-1)
alerts = result_store.load_alerts(selected_run)

c1, c2 = st.columns(2)
c1.metric("Total alerts", len(alerts))
unique_rules = len({a.get("rule_id") for a in alerts if a.get("rule_id")})
c2.metric("Unique rules fired", unique_rules)

if alerts:
    st.divider()
    st.markdown("### Alert breakdown")
    rows = [{"Rule ID": a.get("rule_id", "?"), "Scenario": a.get("scenario_id", "?")} for a in alerts]
    df = pd.DataFrame(rows)
    rule_counts = df.groupby("Rule ID").size().reset_index(name="Alert Count").sort_values("Alert Count", ascending=False)
    st.dataframe(rule_counts, use_container_width=True, hide_index=True)

    scenario_counts = df.groupby("Scenario").size().reset_index(name="Alerts").sort_values("Alerts", ascending=False)
    with st.expander("By scenario"):
        st.dataframe(scenario_counts, use_container_width=True, hide_index=True)
```

### `ui/pages/deploy_preview.py`

```python
# ui/pages/deploy_preview.py
"""
Deploy Preview — review unique rules and launch deploy via CLI.
"""
import subprocess
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
import streamlit as st

from core.theme import apply_theme
from storage.result_store import ResultStore
from storage.rule_store import RuleStore

_CATALOGS_DIR = Path("catalogs")
_OUTPUT_DIR = Path("output")

apply_theme()
st.title("🚀 Deploy Preview")

store = RuleStore(_CATALOGS_DIR)
result_store = ResultStore(_OUTPUT_DIR)
catalogs = store.list_catalogs()

if len(catalogs) < 2:
    st.warning("Need at least 2 catalogs to preview deployments.")
    st.stop()

with st.sidebar:
    catalog_a = st.selectbox("Source catalog", catalogs, index=0)
    catalog_b = st.selectbox("Target SIEM catalog", catalogs, index=min(1, len(catalogs)-1))

unique_dicts = result_store.load_unique(catalog_a, catalog_b)
decisions = result_store.load_decisions(catalog_a, catalog_b)
add_rules = [k for k, v in decisions.items() if v == "ADD"]

st.caption(
    f"Rules from **{catalog_a}** that are NOT covered by **{catalog_b}** — "
    f"candidates to add to the SIEM."
)

if not unique_dicts:
    st.info(
        "No comparison results yet. Run `dksec compare` first to identify unique rules."
    )
    st.stop()

st.metric(f"Rules to add ({catalog_a} → {catalog_b})", len(unique_dicts))

# Table of rules to deploy
rows = [
    {
        "ID": r.get("id", "?")[:10] + "…",
        "Name": r.get("name", "?"),
        "Severity": r.get("severity", "?"),
        "MITRE": ", ".join((r.get("mitre_techniques") or [])[:3]),
    }
    for r in unique_dicts
]
st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

st.divider()

# Deploy action
st.markdown("### Deploy to SIEM")
col1, col2 = st.columns(2)
dry_run = col1.checkbox("Dry run (preview only)", value=True)
target = col2.text_input("Target", value=catalog_b)

if st.button("🚀 Deploy unique rules", type="primary"):
    cmd = [sys.executable, "-m", "cli", "deploy", "--mode", "permanent",
           "--catalog", catalog_a, "--target", target]
    if dry_run:
        cmd.append("--dry-run")

    with st.spinner("Running deploy…"):
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(Path.cwd()))

    if result.returncode == 0:
        st.success(result.stdout)
    else:
        st.error(result.stderr or result.stdout)
```

### `ui/pages/scoring.py`

```python
# ui/pages/scoring.py
"""
Scoring page — rule scoring & prioritization using core/scoring.py.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
import streamlit as st

from core.scoring import classify_rule, normalize_scores, score_rule
from core.theme import apply_theme
from storage.result_store import ResultStore
from storage.rule_store import RuleStore

_CATALOGS_DIR = Path("catalogs")
_OUTPUT_DIR = Path("output")

apply_theme()
st.title("🏆 Scoring")

store = RuleStore(_CATALOGS_DIR)
result_store = ResultStore(_OUTPUT_DIR)
catalogs = store.list_catalogs()

if not catalogs:
    st.info("No catalogs loaded yet.")
    st.stop()

with st.sidebar:
    catalog = st.selectbox("Catalog to score", catalogs)
    sev_filter = st.multiselect("Severity filter", ["critical", "high", "medium", "low"], default=["critical", "high"])

rules = store.load_all(catalog)

# Load overlap info
overlap_ids: set[str] = set()
for other in catalogs:
    if other != catalog:
        for pair in result_store.load_overlaps(catalog, other):
            overlap_ids.add(pair.get("rule_a_id", ""))

raw_scores = [score_rule(r, r.id in overlap_ids, 0) for r in rules]
norm_scores = normalize_scores(raw_scores)

rows = [
    {
        "Name": r.name,
        "Severity": r.severity,
        "Score": round(ns, 1),
        "Class": classify_rule(0, r.severity),
        "MITRE": ", ".join(r.mitre_techniques[:2]),
        "Overlap": "⚠️" if r.id in overlap_ids else "✅",
    }
    for r, ns in zip(rules, norm_scores)
]

df = pd.DataFrame(rows)
if sev_filter:
    df = df[df["Severity"].isin(sev_filter)]
df = df.sort_values("Score", ascending=False)

st.caption(f"Scoring **{len(df)}** rules from **{catalog}**")
st.dataframe(df, use_container_width=True, hide_index=True)
```

### Add `metric_card_html` to `core/theme.py` if missing

Check `core/theme.py` for `metric_card_html`. If absent, append:

```python
def metric_card_html(title: str, value: str, caption: str, color: str = "#58a6ff") -> str:
    """Return HTML for a single metric card (used in Streamlit with unsafe_allow_html=True)."""
    return (
        f'<div class="metric-card">'
        f'<div style="font-size:2rem;font-weight:700;color:{color}">{value}</div>'
        f'<div style="font-size:0.85rem;color:#8b949e;margin-top:4px">{title}</div>'
        f'<div style="font-size:0.75rem;color:#6e7681;margin-top:2px">{caption}</div>'
        f'</div>'
    )
```

### Run full test suite to confirm no regressions
```python
import subprocess, sys
r = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-q"], capture_output=True, text=True, cwd=r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec")
print(r.stdout, r.stderr)
```
Expected: same count as after Task 1 (no new tests, no regressions)

### Commit
```
git add ui/pages/attack_chain.py ui/pages/deploy_preview.py ui/pages/scoring.py core/theme.py
git commit -m "feat: add attack_chain, deploy_preview, scoring UI pages and theme helpers

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

### Merge to main
```python
import subprocess
cwd = r"C:\Users\kaspe\hobby_proj\DKSec\pub_DKSec"
r = subprocess.run(["git", "checkout", "main"], cwd=cwd, capture_output=True, text=True)
r2 = subprocess.run(["git", "merge", "plan6-cli-ui", "--no-ff", "-m",
    "feat: merge Plan 6 CLI and UI into main\n\nCo-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"],
    cwd=cwd, capture_output=True, text=True)
print(r.stdout, r.stderr, r2.stdout, r2.stderr)
# Verify
r3 = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-q"], capture_output=True, text=True, cwd=cwd)
print(r3.stdout)
# Delete branch
subprocess.run(["git", "branch", "-d", "plan6-cli-ui"], cwd=cwd, capture_output=True)
```
