# DKSec Plan 7 — UX Review Improvements

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement 5 actionable improvements from the 3rd-party review to make the comparison UI a complete decision-making workflow — with an actionable gap list, side-by-side overlap views, a per-rule triage system, a fixed deploy flow, a MITRE coverage heatmap, and clear attack-chain UI state.

**Architecture:** All changes are in `ui/pages/`, `cli.py`, and a new `core/mitre_mapping.py`. No pipeline/ or storage/ changes are needed — we load existing data and augment the UI layer. Per-rule triage decisions are persisted immediately to the existing `output/reports/<a>_vs_<b>_decisions.json` file via ResultStore.

**Tech Stack:** Streamlit (expandable rows, columns, session_state), Click CLI, Python 3.11+, existing RuleAST / ResultStore / RuleStore infrastructure.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `core/mitre_mapping.py` | **Create** | Technique-ID → tactic mapping |
| `cli.py` | **Modify** | Fix `deploy` command to filter ADD-only rules |
| `ui/pages/comparison.py` | **Modify** | Gap list with expanders + triage + heatmap + overlap side-by-side |
| `ui/pages/deploy_preview.py` | **Modify** | Show exact ADD rules + fix subprocess args |
| `ui/pages/attack_chain.py` | **Modify** | Show "setup required" state when no runs exist |
| `tests/test_mitre_mapping.py` | **Create** | Unit tests for MITRE mapping |
| `tests/test_cli_deploy_fix.py` | **Create** | Tests for fixed deploy command behaviour |

---

## Task 1: Fix the deploy count bug in cli.py

This is the trust-critical fix. Currently `cli.py deploy` loads ALL rules from the catalog and deploys them. It must filter to only the rules marked "ADD" in the decisions file.

**Files:**
- Modify: `cli.py` (the `deploy` command, around line 181–205)
- Create: `tests/test_cli_deploy_fix.py`

### Step 1.1 — Write the failing test

```python
# tests/test_cli_deploy_fix.py
from __future__ import annotations

import json
from pathlib import Path
import pytest
from click.testing import CliRunner
from cli import cli

@pytest.fixture
def tmp_project(tmp_path):
    """Set up a minimal catalog + decisions for deploy tests."""
    # Two sigma rules
    cat_dir = tmp_path / "catalogs" / "sigma" / "ast"
    cat_dir.mkdir(parents=True)
    for i, (rid, name) in enumerate([("rule-001", "Alpha"), ("rule-002", "Beta"),
                                      ("rule-003", "Gamma")]):
        (cat_dir / f"{rid}.json").write_text(json.dumps({
            "id": rid, "catalog": "sigma", "name": name,
            "description": "", "severity": "high",
            "mitre_techniques": [], "event_categories": [],
            "conditions": [], "raw_query": "", "language": "sigma",
            "translated_query": None, "source_path": "", "metadata": {}
        }), encoding="utf-8")

    # Decisions: rule-001 ADD, rule-002 SKIP, rule-003 ADD
    rep_dir = tmp_path / "output" / "reports"
    rep_dir.mkdir(parents=True)
    (rep_dir / "sigma_vs_elastic_decisions.json").write_text(
        json.dumps({"rule-001": "ADD", "rule-002": "SKIP", "rule-003": "ADD"}),
        encoding="utf-8"
    )
    return tmp_path


def test_deploy_dry_run_only_add_rules(tmp_project, monkeypatch):
    """Dry-run deploy must report only ADD-decision rules, not all catalog rules."""
    monkeypatch.setenv("DKSEC_CATALOGS", str(tmp_project / "catalogs"))
    monkeypatch.setenv("DKSEC_OUTPUT", str(tmp_project / "output"))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "deploy", "--mode", "permanent", "--catalog", "sigma",
        "--target", "elastic", "--compare-catalog", "elastic", "--dry-run"
    ])
    assert result.exit_code == 0, result.output
    # Should say 2 rules (rule-001 and rule-003 are ADD), NOT 3
    assert "2 rules" in result.output
    assert "3 rules" not in result.output


def test_deploy_dry_run_no_decisions_falls_back_to_all(tmp_project, monkeypatch):
    """If no decisions file exists, deploy all rules and warn."""
    monkeypatch.setenv("DKSEC_CATALOGS", str(tmp_project / "catalogs"))
    monkeypatch.setenv("DKSEC_OUTPUT", str(tmp_project / "output"))
    runner = CliRunner()
    # Use a catalog pair with no decision file
    result = runner.invoke(cli, [
        "deploy", "--mode", "permanent", "--catalog", "sigma",
        "--target", "splunk", "--compare-catalog", "splunk", "--dry-run"
    ])
    assert result.exit_code == 0
    assert "3 rules" in result.output  # all 3 rules (no filter)
```

- [ ] **Step 1.1: Write the test file above** to `tests/test_cli_deploy_fix.py`

- [ ] **Step 1.2: Run to confirm FAIL**

```
python -m pytest tests/test_cli_deploy_fix.py -v
```
Expected: FAIL — `unrecognized option --compare-catalog`

- [ ] **Step 1.3: Modify `cli.py` deploy command**

Replace the existing `deploy` command (approx lines 181–205) with:

```python
@cli.command()
@click.option(
    "--mode", required=True,
    type=click.Choice(["test", "permanent"]),
    help="'test' = tagged temporary deploy; 'permanent' = persist unique rules",
)
@click.option("--catalog", required=True, help="Catalog to deploy")
@click.option("--target", required=True, help="Target SIEM (e.g. elastic)")
@click.option(
    "--compare-catalog", "compare_catalog", default=None,
    help="SIEM catalog used during compare step (to look up ADD decisions). "
         "If omitted, all rules are deployed.",
)
@click.option("--dry-run", is_flag=True, default=False, help="Print rules without deploying")
def deploy(mode: str, catalog: str, target: str, compare_catalog: str | None, dry_run: bool):
    """Step 3 (test) / Step 6 (permanent): Deploy rules to SIEM.

    When --compare-catalog is provided, only rules marked ADD in the decisions
    file are deployed. Without it, all rules in the catalog are deployed.
    """
    store = _rule_store()
    result_store = _result_store()
    all_rules = store.load_all(catalog)

    if compare_catalog:
        decisions = result_store.load_decisions(catalog, compare_catalog)
        if decisions:
            rules = [r for r in all_rules if decisions.get(r.id) == "ADD"]
            if not rules:
                click.echo(
                    f"No ADD-decision rules found for '{catalog}' vs '{compare_catalog}'. "
                    "Nothing to deploy."
                )
                return
        else:
            click.echo(
                f"Warning: no decisions file for '{catalog}' vs '{compare_catalog}'. "
                "Deploying all rules."
            )
            rules = all_rules
    else:
        rules = all_rules

    if dry_run:
        click.echo(
            f"Dry-run: would deploy {len(rules)} rules from '{catalog}' to '{target}' [{mode}]"
        )
        for r in rules:
            click.echo(f"  - [{r.severity}] {r.name}")
        return

    adapter = _make_adapter(target, "api", path=None, url=None)
    result = deploy_rules(adapter, rules, client=None, mode=mode)
    status = "WARNING" if result.failed_count else "OK"
    click.echo(
        f"[{status}] Deployed {result.deployed_count} rules "
        f"({result.failed_count} failed) [{mode}] -> {target}"
    )
    for err in result.errors[:5]:
        click.echo(f"  -> {err}", err=True)
```

- [ ] **Step 1.4: Run tests**

```
python -m pytest tests/test_cli_deploy_fix.py -v
```
Expected: 2/2 PASS

- [ ] **Step 1.5: Run full test suite**

```
python -m pytest tests/ -q
```
Expected: all existing tests still pass

- [ ] **Step 1.6: Commit**

```
git add cli.py tests/test_cli_deploy_fix.py
git commit -m "fix: deploy command filters to ADD-decision rules only"
```

---

## Task 2: Fix deploy_preview.py to match the fixed CLI

Update the Deploy Preview page to pass `--compare-catalog` and show the exact rules that will be deployed.

**Files:**
- Modify: `ui/pages/deploy_preview.py`

- [ ] **Step 2.1: Rewrite `ui/pages/deploy_preview.py`**

Replace the entire file content with:

```python
# ui/pages/deploy_preview.py
"""Deploy Preview — review ADD-decision rules and launch deploy via CLI."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
import streamlit as st

from core.ast_model import RuleAST
from core.theme import apply_theme
from storage.result_store import ResultStore
from storage.rule_store import RuleStore

_ROOT = Path(__file__).parent.parent.parent
_CATALOGS_DIR = _ROOT / "catalogs"
_OUTPUT_DIR = _ROOT / "output"

apply_theme()
st.title("🚀 Deploy Preview")

store = RuleStore(_CATALOGS_DIR)
result_store = ResultStore(_OUTPUT_DIR)
catalogs = store.list_catalogs()

if len(catalogs) < 2:
    st.warning("Need at least 2 catalogs to preview deployments.")
    st.stop()

with st.sidebar:
    _SIEM_CATALOGS = {"elastic", "sentinel", "splunk", "qradar", "chronicle"}
    non_siem = [c for c in catalogs if c not in _SIEM_CATALOGS]
    src_idx = catalogs.index(non_siem[0]) if non_siem else 0
    catalog_a = st.selectbox("Source ruleset", catalogs, index=src_idx,
                              help="External ruleset (e.g. Sigma)")
    remaining = [c for c in catalogs if c != catalog_a]
    catalog_b = st.selectbox("Target SIEM catalog", remaining if remaining else catalogs,
                              help="Your SIEM (e.g. Elastic)")

decisions = result_store.load_decisions(catalog_a, catalog_b)
unique_dicts = result_store.load_unique(catalog_a, catalog_b)

st.caption(
    f"Rules from **{catalog_a}** not covered by **{catalog_b}** — "
    "candidates to add to the SIEM."
)

if not unique_dicts:
    st.info(
        "No comparison results yet.  \n"
        f"Run `dksec compare --a {catalog_a} --b {catalog_b}` first."
    )
    st.stop()

# Split rules by decision status
add_rules = [r for r in unique_dicts if decisions.get(r.get("id")) == "ADD"]
skip_rules = [r for r in unique_dicts if decisions.get(r.get("id")) == "SKIP"]
review_rules = [r for r in unique_dicts if decisions.get(r.get("id")) == "REVIEW"]
undecided = [r for r in unique_dicts if r.get("id") not in decisions]

# Summary metrics
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total unique", len(unique_dicts))
c2.metric("ADD (deploy)", len(add_rules))
c3.metric("SKIP", len(skip_rules))
c4.metric("Undecided", len(undecided))

if not add_rules:
    st.warning(
        f"No rules are marked ADD yet. Use the **Comparison** page to triage rules, "
        "or run `dksec decide` to auto-generate decisions."
    )
else:
    st.divider()
    st.markdown(f"### Rules queued for deploy ({len(add_rules)})")
    st.caption("These are the **only** rules that will be sent to the SIEM.")

    for r in add_rules:
        with st.expander(f"[{r.get('severity','?').upper()}] {r.get('name','?')}"):
            st.markdown(f"**ID:** `{r.get('id','?')}`")
            st.markdown(f"**Description:** {r.get('description') or '_No description_'}")
            tq = r.get("translated_query") or r.get("raw_query") or "_No query_"
            st.code(tq, language="sql")
            mitre = ", ".join((r.get("mitre_techniques") or [])[:5])
            if mitre:
                st.caption(f"MITRE: {mitre}")

st.divider()
st.markdown("### Deploy to SIEM")

if not add_rules:
    st.info("Triage rules on the Comparison page first, then return here to deploy.")
    st.stop()

col1, col2 = st.columns(2)
dry_run = col1.checkbox("Dry run (preview only)", value=True)
target = col2.text_input("Target SIEM name", value=catalog_b)

st.warning(
    f"This will deploy **{len(add_rules)} rules** from `{catalog_a}` to `{target}`.  \n"
    f"{'(DRY RUN — no changes will be made)' if dry_run else '**LIVE DEPLOY — rules will be created in the SIEM.**'}"
)

if st.button("🚀 Deploy ADD rules", type="primary"):
    cmd = [
        sys.executable,
        str(_ROOT / "cli.py"),
        "deploy",
        "--mode", "permanent",
        "--catalog", catalog_a,
        "--target", target,
        "--compare-catalog", catalog_b,
    ]
    if dry_run:
        cmd.append("--dry-run")

    with st.spinner("Running deploy…"):
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(_ROOT),
        )

    if proc.returncode == 0:
        st.success(proc.stdout or "Deploy completed.")
    else:
        st.error(proc.stderr or proc.stdout or "Deploy failed.")
```

- [ ] **Step 2.2: Run the Streamlit app and verify the Deploy Preview page**

```
streamlit run ui/dashboard.py
```

Navigate to Deploy Preview. Confirm:
- Shows 4 metrics: Total unique, ADD, SKIP, Undecided
- If `dksec decide` has been run, shows the ADD-decision rules as expandable rows with description + query
- Deploy button says "deploy N rules" where N matches the ADD count, not the total catalog count

- [ ] **Step 2.3: Commit**

```
git add ui/pages/deploy_preview.py
git commit -m "fix: deploy preview shows only ADD-decision rules with exact count"
```

---

## Task 3: MITRE technique → tactic mapping module

Create a lightweight mapping from technique IDs like "attack.t1059.001" or "T1059" to MITRE ATT&CK tactic names. This is used by the heatmap in Task 5.

**Files:**
- Create: `core/mitre_mapping.py`
- Create: `tests/test_mitre_mapping.py`

- [ ] **Step 3.1: Write the failing tests**

```python
# tests/test_mitre_mapping.py
from __future__ import annotations

import pytest
from core.mitre_mapping import technique_to_tactics, rules_coverage_by_tactic

# We use lightweight technique→tactic lookup (a single technique can belong to
# multiple tactics in ATT&CK, but we map to the primary ones).
# Technique IDs may arrive as "T1059.001", "attack.t1059.001", or "t1059".


def test_technique_id_parsing_attack_prefix():
    tactics = technique_to_tactics("attack.t1059.001")
    assert "Execution" in tactics


def test_technique_id_parsing_uppercase():
    tactics = technique_to_tactics("T1059")
    assert "Execution" in tactics


def test_technique_id_parsing_lowercase_no_prefix():
    tactics = technique_to_tactics("t1003")
    assert "Credential Access" in tactics


def test_unknown_technique_returns_empty():
    tactics = technique_to_tactics("T9999")
    assert tactics == []


def test_persistence_technique():
    tactics = technique_to_tactics("T1053.005")
    assert "Persistence" in tactics or "Execution" in tactics  # schtasks = both


def test_lateral_movement_technique():
    tactics = technique_to_tactics("T1021")
    assert "Lateral Movement" in tactics


def test_rules_coverage_by_tactic_basic():
    """Coverage dict maps each tactic to a count of rules that cover it."""
    rules = [
        {"mitre_techniques": ["attack.t1059.001", "attack.t1003.001"]},
        {"mitre_techniques": ["attack.t1059.001"]},
        {"mitre_techniques": []},
    ]
    cov = rules_coverage_by_tactic(rules)
    assert cov["Execution"] == 2
    assert cov["Credential Access"] == 1
    # Tactics with no rules should be present with count 0
    assert cov.get("Lateral Movement", 0) == 0


def test_rules_coverage_by_tactic_deduplicates_per_rule():
    """One rule with 2 techniques in the same tactic counts as 1 for that tactic."""
    rules = [
        {"mitre_techniques": ["attack.t1059.001", "attack.t1059.003"]},
    ]
    cov = rules_coverage_by_tactic(rules)
    assert cov["Execution"] == 1  # same tactic, different sub-techniques → 1 rule


def test_all_tactics_present_in_coverage():
    """coverage_by_tactic returns all 14 ATT&CK tactics, even with count 0."""
    cov = rules_coverage_by_tactic([])
    expected_tactics = {
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact",
        "Reconnaissance", "Resource Development",
    }
    assert expected_tactics.issubset(set(cov.keys()))
```

- [ ] **Step 3.2: Run to confirm FAIL**

```
python -m pytest tests/test_mitre_mapping.py -v
```
Expected: FAIL — `ModuleNotFoundError: No module named 'core.mitre_mapping'`

- [ ] **Step 3.3: Create `core/mitre_mapping.py`**

```python
# core/mitre_mapping.py
"""Lightweight MITRE ATT&CK technique → tactic mapping.

Technique IDs are normalised before lookup:
  "attack.t1059.001" → "T1059"
  "T1059.001"        → "T1059"
  "t1059"            → "T1059"

Each base technique maps to one or more tactic names.
Only base technique IDs (no sub-technique suffix) are used for lookup so that
T1059.001 and T1059.003 both resolve through T1059.
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Technique → Tactic mapping
# ---------------------------------------------------------------------------
# Source: MITRE ATT&CK Enterprise v14 (primary tactics only).
# Techniques that appear in multiple tactics list all of them.

_TECHNIQUE_TACTICS: dict[str, list[str]] = {
    # Initial Access
    "T1078": ["Initial Access", "Defense Evasion", "Persistence", "Privilege Escalation"],
    "T1091": ["Initial Access", "Lateral Movement"],
    "T1133": ["Initial Access", "Persistence"],
    "T1189": ["Initial Access"],
    "T1190": ["Initial Access"],
    "T1195": ["Initial Access"],
    "T1199": ["Initial Access"],
    "T1566": ["Initial Access"],
    # Execution
    "T1047": ["Execution"],
    "T1053": ["Execution", "Persistence", "Privilege Escalation"],
    "T1059": ["Execution"],
    "T1072": ["Execution", "Lateral Movement"],
    "T1106": ["Execution"],
    "T1129": ["Execution"],
    "T1204": ["Execution"],
    "T1559": ["Execution"],
    "T1610": ["Execution"],
    # Persistence
    "T1037": ["Persistence", "Privilege Escalation"],
    "T1098": ["Persistence", "Privilege Escalation"],
    "T1136": ["Persistence"],
    "T1137": ["Persistence"],
    "T1176": ["Persistence"],
    "T1197": ["Defense Evasion", "Persistence"],
    "T1505": ["Persistence"],
    "T1525": ["Persistence"],
    "T1542": ["Defense Evasion", "Persistence"],
    "T1543": ["Persistence", "Privilege Escalation"],
    "T1546": ["Persistence", "Privilege Escalation"],
    "T1547": ["Persistence", "Privilege Escalation"],
    "T1554": ["Persistence"],
    "T1556": ["Credential Access", "Defense Evasion", "Persistence"],
    "T1574": ["Defense Evasion", "Persistence", "Privilege Escalation"],
    # Privilege Escalation
    "T1055": ["Defense Evasion", "Privilege Escalation"],
    "T1068": ["Privilege Escalation"],
    "T1134": ["Defense Evasion", "Privilege Escalation"],
    "T1484": ["Defense Evasion", "Privilege Escalation"],
    "T1548": ["Defense Evasion", "Privilege Escalation"],
    "T1611": ["Privilege Escalation"],
    # Defense Evasion
    "T1006": ["Defense Evasion"],
    "T1014": ["Defense Evasion"],
    "T1027": ["Defense Evasion"],
    "T1036": ["Defense Evasion"],
    "T1070": ["Defense Evasion"],
    "T1112": ["Defense Evasion"],
    "T1140": ["Defense Evasion"],
    "T1202": ["Defense Evasion"],
    "T1205": ["Command and Control", "Defense Evasion", "Persistence"],
    "T1207": ["Defense Evasion"],
    "T1218": ["Defense Evasion"],
    "T1220": ["Defense Evasion"],
    "T1480": ["Defense Evasion"],
    "T1562": ["Defense Evasion"],
    "T1564": ["Defense Evasion"],
    "T1600": ["Defense Evasion"],
    "T1620": ["Defense Evasion"],
    # Credential Access
    "T1003": ["Credential Access"],
    "T1056": ["Collection", "Credential Access"],
    "T1110": ["Credential Access"],
    "T1111": ["Credential Access"],
    "T1187": ["Credential Access"],
    "T1212": ["Credential Access"],
    "T1528": ["Credential Access"],
    "T1539": ["Credential Access"],
    "T1552": ["Credential Access"],
    "T1557": ["Collection", "Credential Access"],
    "T1558": ["Credential Access"],
    "T1606": ["Credential Access"],
    # Discovery
    "T1007": ["Discovery"],
    "T1010": ["Discovery"],
    "T1012": ["Discovery"],
    "T1016": ["Discovery"],
    "T1018": ["Discovery"],
    "T1033": ["Discovery"],
    "T1040": ["Collection", "Discovery"],
    "T1049": ["Discovery"],
    "T1057": ["Discovery"],
    "T1069": ["Discovery"],
    "T1082": ["Discovery"],
    "T1083": ["Discovery"],
    "T1087": ["Discovery"],
    "T1120": ["Discovery"],
    "T1124": ["Discovery"],
    "T1135": ["Discovery"],
    "T1201": ["Discovery"],
    "T1217": ["Discovery"],
    "T1482": ["Discovery"],
    "T1518": ["Discovery"],
    "T1526": ["Discovery"],
    "T1538": ["Discovery"],
    "T1580": ["Discovery"],
    "T1613": ["Discovery"],
    # Lateral Movement
    "T1021": ["Lateral Movement"],
    "T1080": ["Lateral Movement"],
    "T1210": ["Lateral Movement"],
    "T1534": ["Lateral Movement"],
    "T1550": ["Defense Evasion", "Lateral Movement"],
    "T1563": ["Lateral Movement"],
    "T1570": ["Lateral Movement"],
    # Collection
    "T1005": ["Collection"],
    "T1025": ["Collection"],
    "T1039": ["Collection"],
    "T1074": ["Collection"],
    "T1113": ["Collection"],
    "T1114": ["Collection"],
    "T1115": ["Collection"],
    "T1119": ["Collection"],
    "T1123": ["Collection"],
    "T1125": ["Collection"],
    "T1185": ["Collection"],
    "T1213": ["Collection"],
    "T1530": ["Collection"],
    "T1560": ["Collection"],
    # Command and Control
    "T1001": ["Command and Control"],
    "T1008": ["Command and Control"],
    "T1071": ["Command and Control"],
    "T1090": ["Command and Control"],
    "T1095": ["Command and Control"],
    "T1102": ["Command and Control"],
    "T1104": ["Command and Control"],
    "T1105": ["Command and Control"],
    "T1132": ["Command and Control"],
    "T1219": ["Command and Control"],
    "T1568": ["Command and Control"],
    "T1571": ["Command and Control"],
    "T1572": ["Command and Control"],
    "T1573": ["Command and Control"],
    # Exfiltration
    "T1011": ["Exfiltration"],
    "T1020": ["Exfiltration"],
    "T1029": ["Exfiltration"],
    "T1030": ["Exfiltration"],
    "T1041": ["Exfiltration"],
    "T1048": ["Exfiltration"],
    "T1052": ["Exfiltration"],
    "T1537": ["Exfiltration"],
    "T1567": ["Exfiltration"],
    # Impact
    "T1485": ["Impact"],
    "T1486": ["Impact"],
    "T1489": ["Impact"],
    "T1490": ["Impact"],
    "T1491": ["Impact"],
    "T1495": ["Impact"],
    "T1496": ["Impact"],
    "T1498": ["Impact"],
    "T1499": ["Impact"],
    "T1529": ["Impact"],
    "T1531": ["Impact"],
    "T1561": ["Impact"],
    "T1565": ["Impact"],
    # Reconnaissance
    "T1591": ["Reconnaissance"],
    "T1592": ["Reconnaissance"],
    "T1593": ["Reconnaissance"],
    "T1594": ["Reconnaissance"],
    "T1595": ["Reconnaissance"],
    "T1596": ["Reconnaissance"],
    "T1597": ["Reconnaissance"],
    "T1598": ["Reconnaissance"],
    # Resource Development
    "T1583": ["Resource Development"],
    "T1584": ["Resource Development"],
    "T1585": ["Resource Development"],
    "T1586": ["Resource Development"],
    "T1587": ["Resource Development"],
    "T1588": ["Resource Development"],
    "T1589": ["Resource Development"],
    "T1590": ["Resource Development"],
    "T1608": ["Resource Development"],
}

ALL_TACTICS: list[str] = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
    "Reconnaissance",
    "Resource Development",
]


def _normalise_technique_id(raw: str) -> str:
    """Convert any format of technique ID to normalised 'TXXXX' (no sub-technique)."""
    # Strip "attack." prefix and lowercase
    cleaned = re.sub(r"^attack\.", "", raw.strip(), flags=re.IGNORECASE)
    # Remove sub-technique suffix (.001, .002, etc.)
    cleaned = re.sub(r"\.\d+$", "", cleaned)
    # Uppercase and ensure T prefix
    cleaned = cleaned.upper()
    if not cleaned.startswith("T"):
        cleaned = "T" + cleaned
    return cleaned


def technique_to_tactics(technique_id: str) -> list[str]:
    """Return the list of tactic names for a technique ID string.

    Accepts formats: "T1059.001", "attack.t1059.001", "t1059".
    Returns [] for unknown techniques.
    """
    normalised = _normalise_technique_id(technique_id)
    return list(_TECHNIQUE_TACTICS.get(normalised, []))


def rules_coverage_by_tactic(rules: list[dict]) -> dict[str, int]:
    """Count unique rules covering each ATT&CK tactic.

    Each rule is counted at most once per tactic, even if it has multiple
    techniques that map to the same tactic.

    Args:
        rules: List of rule dicts (must have 'mitre_techniques' key).

    Returns:
        Dict mapping every tactic name (all 14) to a count >= 0.
    """
    counts: dict[str, int] = {tactic: 0 for tactic in ALL_TACTICS}

    for rule in rules:
        techniques = rule.get("mitre_techniques") or []
        covered_tactics: set[str] = set()
        for tech in techniques:
            covered_tactics.update(technique_to_tactics(tech))
        for tactic in covered_tactics:
            if tactic in counts:
                counts[tactic] += 1

    return counts
```

- [ ] **Step 3.4: Run tests**

```
python -m pytest tests/test_mitre_mapping.py -v
```
Expected: 8/8 PASS

- [ ] **Step 3.5: Run full suite**

```
python -m pytest tests/ -q
```
Expected: all passing

- [ ] **Step 3.6: Commit**

```
git add core/mitre_mapping.py tests/test_mitre_mapping.py
git commit -m "feat: add MITRE technique-to-tactic mapping module"
```

---

## Task 4: Actionable gap list with inline triage

Replace the flat dataframe in `comparison.py` with per-rule expanders that show description, conditions, and translated query. Add triage buttons (ADD / SKIP / NEEDS REVIEW) that save decisions immediately.

**Files:**
- Modify: `ui/pages/comparison.py`

This is a UI-only change — no new tests needed (Streamlit pages cannot be unit-tested with pytest). Verify manually.

- [ ] **Step 4.1: Rewrite `ui/pages/comparison.py`**

Replace the entire file with:

```python
# ui/pages/comparison.py
"""Comparison page — catalog picker + overlap/unique analysis + inline triage."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
import streamlit as st

from core.mitre_mapping import rules_coverage_by_tactic, ALL_TACTICS
from core.theme import apply_theme
from pipeline.compare import compare_rules
from storage.result_store import ResultStore
from storage.rule_store import RuleStore

_ROOT = Path(__file__).parent.parent.parent
_CATALOGS_DIR = _ROOT / "catalogs"
_OUTPUT_DIR = _ROOT / "output"

apply_theme()
st.title("📊 Comparison")

store = RuleStore(_CATALOGS_DIR)
result_store = ResultStore(_OUTPUT_DIR)
catalogs = store.list_catalogs()

_SIEM_CATALOGS = {"elastic", "sentinel", "splunk", "qradar", "chronicle"}


def _default_source(cats: list[str]) -> int:
    for i, c in enumerate(cats):
        if c not in _SIEM_CATALOGS:
            return i
    return 0


if len(catalogs) < 2:
    st.warning(
        "Need at least 2 catalogs loaded.  \n"
        "Run `dksec ingest` for each catalog first."
    )
    st.stop()

with st.sidebar:
    st.markdown("**Comparison settings**")
    src_idx = _default_source(catalogs)
    catalog_a = st.selectbox("Source ruleset", catalogs, index=src_idx, key="cmp_a",
                              help="External ruleset to evaluate (e.g. Sigma)")
    remaining = [c for c in catalogs if c != catalog_a]
    catalog_b = st.selectbox("Target SIEM", remaining if remaining else catalogs,
                              key="cmp_b", help="Your SIEM's existing ruleset (e.g. Elastic)")
    threshold = st.slider("Jaccard threshold", 0.05, 0.80, 0.15, 0.05)
    run_id = None
    runs = result_store.list_alert_runs()
    if runs:
        use_alerts = st.checkbox("Include alert data", value=True)
        if use_alerts:
            run_id = st.selectbox("Attack run", runs, index=len(runs) - 1)

if catalog_a == catalog_b:
    st.error("Select two different catalogs.")
    st.stop()

rules_a = store.load_all(catalog_a)
rules_b = store.load_all(catalog_b)

if not rules_a or not rules_b:
    st.warning("One or both catalogs are empty. Run `dksec ingest` and `dksec translate` first.")
    st.stop()

alerts = result_store.load_alerts(run_id) if run_id else None

with st.spinner("Analysing coverage…"):
    result = compare_rules(rules_a, rules_b, alerts=alerts, threshold=threshold)

# Persist results
overlaps_dicts, unique_a_dicts = result.to_storage_dicts()
result_store.save_overlaps(catalog_a, catalog_b, overlaps_dicts)
result_store.save_unique(catalog_a, catalog_b, unique_a_dicts)
result_store.save_unique(catalog_b, catalog_a, [r.to_dict() for r in result.unique_b])

# Load existing decisions (persisted from previous sessions)
decisions: dict[str, str] = result_store.load_decisions(catalog_a, catalog_b)

# Summary metrics
c1, c2, c3, c4 = st.columns(4)
c1.metric(f"{catalog_a.title()} rules", len(rules_a))
c2.metric(f"{catalog_b.title()} rules", len(rules_b))
c3.metric("Overlaps", len(result.overlaps))
c4.metric(f"Gaps (add to {catalog_b.title()})", len(result.unique_a))

st.caption(f"Confidence: **{result.confidence}**")
st.divider()

# ── TAB LAYOUT ──────────────────────────────────────────────────────────────
tab_gaps, tab_overlaps, tab_heatmap = st.tabs([
    f"🎯 Gaps — {catalog_a.title()} rules to add ({len(result.unique_a)})",
    f"🔗 Overlaps ({len(result.overlaps)})",
    "🗺️ MITRE Heatmap",
])

# ── TAB 1: GAP LIST (actionable) ─────────────────────────────────────────────
with tab_gaps:
    st.markdown(
        f"Rules from **{catalog_a}** that have **no equivalent** in **{catalog_b}**. "
        "Triage each rule, then go to **Deploy Preview** to push them."
    )

    if not result.unique_a:
        st.success(f"All {catalog_a} rules are already covered by {catalog_b}. Nothing to add.")
    else:
        # Severity filter
        sev_filter = st.multiselect(
            "Filter by severity", ["critical", "high", "medium", "low"],
            default=["critical", "high"],
            key="gap_sev_filter",
        )

        # Triage summary
        add_count = sum(1 for r in result.unique_a if decisions.get(r.id) == "ADD")
        skip_count = sum(1 for r in result.unique_a if decisions.get(r.id) == "SKIP")
        review_count = sum(1 for r in result.unique_a if decisions.get(r.id) == "REVIEW")
        undecided_count = len(result.unique_a) - add_count - skip_count - review_count

        tc1, tc2, tc3, tc4 = st.columns(4)
        tc1.metric("ADD", add_count)
        tc2.metric("SKIP", skip_count)
        tc3.metric("Needs Review", review_count)
        tc4.metric("Undecided", undecided_count)

        filtered = [r for r in result.unique_a
                    if not sev_filter or r.severity in sev_filter]

        if not filtered:
            st.info("No rules match the current severity filter.")
        else:
            for rule in filtered:
                current_decision = decisions.get(rule.id, "UNDECIDED")
                badge = {"ADD": "✅", "SKIP": "⏭️", "REVIEW": "🔍", "UNDECIDED": "❓"}.get(
                    current_decision, "❓"
                )
                with st.expander(
                    f"{badge} [{rule.severity.upper()}] {rule.name}",
                    expanded=(current_decision == "UNDECIDED"),
                ):
                    st.markdown(f"**Description:** {rule.description or '_No description provided._'}")

                    if rule.conditions:
                        st.markdown("**Conditions:**")
                        cond_lines = [
                            f"- `{c.field}` {c.operator} `{', '.join(c.values)}`"
                            for c in rule.conditions
                        ]
                        st.markdown("\n".join(cond_lines))

                    query = rule.translated_query or rule.raw_query or "_No query available_"
                    st.markdown("**Query:**")
                    st.code(query, language="sql")

                    mitre = ", ".join(rule.mitre_techniques[:5])
                    if mitre:
                        st.caption(f"MITRE: {mitre}")

                    # Triage buttons
                    st.markdown("**Triage:**")
                    b1, b2, b3 = st.columns(3)
                    if b1.button("✅ ADD", key=f"add_{rule.id}", use_container_width=True,
                                 type="primary" if current_decision == "ADD" else "secondary"):
                        decisions[rule.id] = "ADD"
                        result_store.save_decisions(catalog_a, catalog_b, decisions)
                        st.rerun()
                    if b2.button("⏭️ SKIP", key=f"skip_{rule.id}", use_container_width=True,
                                 type="primary" if current_decision == "SKIP" else "secondary"):
                        decisions[rule.id] = "SKIP"
                        result_store.save_decisions(catalog_a, catalog_b, decisions)
                        st.rerun()
                    if b3.button("🔍 Needs Review", key=f"review_{rule.id}", use_container_width=True,
                                 type="primary" if current_decision == "REVIEW" else "secondary"):
                        decisions[rule.id] = "REVIEW"
                        result_store.save_decisions(catalog_a, catalog_b, decisions)
                        st.rerun()

# ── TAB 2: OVERLAPS (side-by-side) ───────────────────────────────────────────
with tab_overlaps:
    if not result.overlaps:
        st.caption("No overlaps found at the current threshold.")
    else:
        st.markdown(
            f"**{len(result.overlaps)} rules** in **{catalog_a}** have an equivalent in **{catalog_b}**. "
            "Expand any row to see both rules side-by-side."
        )

        # Quick sort by Jaccard descending
        sorted_overlaps = sorted(result.overlaps, key=lambda p: p.jaccard_score, reverse=True)

        for pair in sorted_overlaps:
            alert_tag = " 🚨" if pair.alert_confirmed else ""
            with st.expander(
                f"**{pair.rule_a.name}** ↔ **{pair.rule_b.name}** "
                f"— Jaccard {pair.jaccard_score:.3f}{alert_tag}"
            ):
                col_a, col_b = st.columns(2)

                with col_a:
                    st.markdown(f"**{catalog_a.title()}: {pair.rule_a.name}**")
                    st.caption(f"Severity: {pair.rule_a.severity} | MITRE: {', '.join(pair.rule_a.mitre_techniques[:3])}")
                    st.markdown(f"_{pair.rule_a.description or 'No description.'}_")
                    if pair.rule_a.conditions:
                        cond_lines = [
                            f"- `{c.field}` {c.operator} `{', '.join(c.values)}`"
                            for c in pair.rule_a.conditions
                        ]
                        st.markdown("**Conditions:**\n" + "\n".join(cond_lines))
                    q_a = pair.rule_a.translated_query or pair.rule_a.raw_query or "_None_"
                    st.code(q_a, language="sql")

                with col_b:
                    st.markdown(f"**{catalog_b.title()}: {pair.rule_b.name}**")
                    st.caption(f"Severity: {pair.rule_b.severity} | MITRE: {', '.join(pair.rule_b.mitre_techniques[:3])}")
                    st.markdown(f"_{pair.rule_b.description or 'No description.'}_")
                    if pair.rule_b.conditions:
                        cond_lines = [
                            f"- `{c.field}` {c.operator} `{', '.join(c.values)}`"
                            for c in pair.rule_b.conditions
                        ]
                        st.markdown("**Conditions:**\n" + "\n".join(cond_lines))
                    q_b = pair.rule_b.translated_query or pair.rule_b.raw_query or "_None_"
                    st.code(q_b, language="sql")

                if pair.alert_confirmed:
                    st.success("Alert-confirmed overlap: both rules fired on the same attack scenario.")

# ── TAB 3: MITRE HEATMAP ─────────────────────────────────────────────────────
with tab_heatmap:
    st.markdown(
        f"Coverage of ATT&CK tactics in **{catalog_b}** (your SIEM). "
        "Darker = more rules covering that tactic."
    )

    all_b_dicts = [r.to_dict() for r in rules_b]
    gap_dicts = [r.to_dict() for r in result.unique_a]

    siem_coverage = rules_coverage_by_tactic(all_b_dicts)
    gap_coverage = rules_coverage_by_tactic(gap_dicts)

    # Build a display dataframe
    heatmap_rows = []
    for tactic in ALL_TACTICS:
        siem_count = siem_coverage.get(tactic, 0)
        gap_count = gap_coverage.get(tactic, 0)
        total = siem_count + gap_count
        pct = int(100 * siem_count / total) if total > 0 else 0
        heatmap_rows.append({
            "Tactic": tactic,
            f"{catalog_b.title()} rules": siem_count,
            f"Gaps (uncovered)": gap_count,
            "Coverage %": pct,
        })

    import pandas as pd
    df_heatmap = pd.DataFrame(heatmap_rows)

    st.dataframe(
        df_heatmap.style.background_gradient(
            subset=["Coverage %"], cmap="RdYlGn", vmin=0, vmax=100
        ).format({"Coverage %": "{}%"}),
        use_container_width=True,
        hide_index=True,
    )

    st.caption(
        "Coverage % = (SIEM rules) / (SIEM rules + gap rules). "
        "0% means the tactic is entirely uncovered in the SIEM."
    )
```

- [ ] **Step 4.2: Launch UI and verify**

```
streamlit run ui/dashboard.py
```

Checks:
- Comparison page has 3 tabs: Gaps, Overlaps, MITRE Heatmap
- Gap tab shows expandable rule rows (expanded by default for undecided)
- Each row shows description, conditions, query, MITRE tags
- ADD / SKIP / Needs Review buttons change the badge on the expander header (after rerun)
- Overlap tab shows pairs sortable by Jaccard, each expandable to two-column view
- Heatmap tab shows a coloured table with coverage percentages

- [ ] **Step 4.3: Commit**

```
git add ui/pages/comparison.py
git commit -m "feat: actionable gap list with triage, side-by-side overlaps, MITRE heatmap"
```

---

## Task 5: Attack Chain UI — clear "setup required" state

When no attack runs exist, replace the empty table with a rich informational screen so engineers understand the feature isn't broken — it just needs CLI setup.

**Files:**
- Modify: `ui/pages/attack_chain.py`

- [ ] **Step 5.1: Rewrite `ui/pages/attack_chain.py`**

Replace the entire file with:

```python
# ui/pages/attack_chain.py
"""Attack Chain page — view attack run history and alert data."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
import streamlit as st

from core.theme import apply_theme
from storage.result_store import ResultStore

_ROOT = Path(__file__).parent.parent.parent
_OUTPUT_DIR = _ROOT / "output"

apply_theme()
st.title("⚔️ Attack Chain")

result_store = ResultStore(_OUTPUT_DIR)
runs = result_store.list_alert_runs()

if not runs:
    st.info("No attack runs recorded yet.")
    st.divider()

    st.markdown("### CLI setup required")
    st.markdown(
        "The Attack Chain feature runs MITRE ATT&CK scenarios against a live environment "
        "and records which detection rules fire. This page displays those results once data exists."
    )

    with st.expander("How to run the attack chain"):
        st.markdown(
            "**Prerequisites:**\n"
            "- A Sliver C2 server running, or Atomic Red Team installed\n"
            "- The target SIEM (Elastic) has the translated rules applied\n\n"
            "**Run:**\n"
            "```bash\n"
            "dksec attack --framework sliver\n"
            "# or\n"
            "dksec attack --framework atomic\n"
            "```\n\n"
            "Results will appear on this page automatically after the run completes."
        )

    with st.expander("What this does"):
        st.markdown(
            "1. Executes pre-defined MITRE ATT&CK scenarios (credential dumping, lateral movement, etc.)\n"
            "2. Polls the SIEM for alerts triggered during the scenario\n"
            "3. Maps each alert back to its source rule\n"
            "4. Uses the alert data to **confirm** or **refute** overlap detections on the Comparison page\n"
            "5. Upgrades comparison confidence from `logic-only` to `full`"
        )

    st.stop()

st.caption(f"**{len(runs)} run(s)** found in output/alerts/")

selected_run = st.selectbox("Select run", runs, index=len(runs) - 1)
alerts = result_store.load_alerts(selected_run)

c1, c2 = st.columns(2)
c1.metric("Total alerts", len(alerts))
unique_rules = len({a.get("rule_id") for a in alerts if a.get("rule_id")})
c2.metric("Unique rules fired", unique_rules)

if not alerts:
    st.info("No alerts in this run.")
    st.stop()

st.divider()
st.markdown("### Alert Breakdown")

rows = [
    {"Rule ID": a.get("rule_id", "?"), "Scenario": a.get("scenario_id", "?")}
    for a in alerts
]
df = pd.DataFrame(rows)
rule_counts = (
    df.groupby("Rule ID")
    .size()
    .reset_index(name="Alert Count")
    .sort_values("Alert Count", ascending=False)
)
st.dataframe(rule_counts, use_container_width=True, hide_index=True)

with st.expander("By scenario"):
    scenario_counts = (
        df.groupby("Scenario")
        .size()
        .reset_index(name="Alerts")
        .sort_values("Alerts", ascending=False)
    )
    st.dataframe(scenario_counts, use_container_width=True, hide_index=True)
```

- [ ] **Step 5.2: Verify UI**

Navigate to the Attack Chain page. With no attack data, you should see:
- "No attack runs recorded yet." info box
- Two expandable sections: "How to run" and "What this does"
- No empty table or confusing blank space

- [ ] **Step 5.3: Commit**

```
git add ui/pages/attack_chain.py
git commit -m "feat: attack chain shows clear CLI setup instructions when no data exists"
```

---

## Task 6: Final integration check

Run all tests and confirm the UI works end-to-end with the seeded data.

- [ ] **Step 6.1: Run full test suite**

```
python -m pytest tests/ -q
```
Expected: all 205+ tests pass (new tests from Tasks 1 and 3 add ~10 more).

- [ ] **Step 6.2: Seed sample data if needed**

```
python scripts/seed_sample_data.py
python cli.py compare --a sigma --b elastic
python cli.py decide --a sigma --b elastic
```

- [ ] **Step 6.3: Launch UI and walk through the full workflow**

```
streamlit run ui/dashboard.py
```

Walkthrough:
1. **Home** — shows overview metrics
2. **Comparison → Gaps tab** — 4 expandable gap rules, each with description/conditions/query + triage buttons. Click ADD on one rule, verify badge changes to ✅
3. **Comparison → Overlaps tab** — expandable pairs with side-by-side columns
4. **Comparison → MITRE Heatmap** — coloured table, all 14 tactics
5. **Deploy Preview** — shows ADD count (matching decisions), expandable rule list with queries, confirms deploy will say "N rules" not 20
6. **Attack Chain** — shows setup instructions (no data)
7. **Scoring** — loads existing rules

- [ ] **Step 6.4: Final commit**

```
git add -A
git commit -m "chore: plan 7 complete — ux review improvements integrated"
```
