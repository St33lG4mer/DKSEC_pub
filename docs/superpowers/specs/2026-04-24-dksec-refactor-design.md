# DKSec Platform Refactor — Design Spec

**Date:** 2026-04-24  
**Status:** Approved  
**Author:** Kasper Gissel / GitHub Copilot

---

## Problem Statement

The current DKSec project is tightly coupled to Sigma and Elastic as hardcoded rule catalogs. `utils.py` (1135 lines) mixes config loading, API clients, comparison logic, scoring, and Streamlit theming. Scripts are flat in the root directory with no shared contract. Adding a third rule catalog (e.g. Splunk, Microsoft Sentinel) would require touching many files with no clear extension point.

The goal of this refactor is to:
1. Establish a **catalog-agnostic pipeline** that can compare any two rule sets.
2. Introduce a **plugin adapter pattern** so new catalogs are added by dropping a single folder under `adapters/`.
3. Make the pipeline **CLI-first**, with Streamlit as a read-only visualization layer.
4. Support **three input source types** per catalog: git repo, local folder, SIEM API.
5. Integrate **both Sliver C2 and Atomic Red Team** for attack chain automation.
6. Clean up the codebase so every file has one clear purpose.

---

## Architecture Overview

```
CLI (cli.py)
    │
    ▼
Pipeline steps (pipeline/)
    ├── ingest.py      → calls adapter.load()
    ├── translate.py   → calls adapter.translate()
    ├── compare.py     → catalog-agnostic Jaccard comparison
    ├── attack_chain.py → orchestrates Sliver / Atomic
    ├── decide.py      → produces ADD/KEEP/SKIP decisions
    └── deploy.py      → calls adapter.deploy()
         │
         ▼
Adapters (adapters/)
    ├── base.py        → BaseAdapter ABC
    ├── sigma/         → SigmaAdapter
    └── elastic/       → ElasticAdapter

Core utilities (core/)
    ├── ast_model.py   → canonical RuleAST dataclass
    ├── normalizer.py  → ECS field normalization
    ├── scoring.py     → rule scoring algorithm
    ├── config.py      → config.yaml loader
    └── theme.py       → Streamlit CSS

Storage (file-based)
    ├── catalogs/<name>/raw/    → fetched raw rules
    ├── catalogs/<name>/ast/    → normalized AST JSON
    └── output/
        ├── overlaps/           → overlap pairs
        ├── unique/             → rules to add to SIEM
        ├── alerts/             → attack chain alert data
        └── reports/            → decisions, comparison reports

UI (ui/) — read-only Streamlit app
    ├── dashboard.py            → entry point
    └── pages/
        ├── home.py
        ├── comparison.py
        ├── catalogs.py
        ├── scoring.py
        ├── attack_chain.py
        └── deploy_preview.py
```

---

## Directory Structure & File Fate

### New / Refactored Layout

```
pub_DKSec/
├── adapters/
│   ├── base.py                      ← NEW: BaseAdapter ABC
│   ├── sigma/
│   │   ├── adapter.py               ← NEW: SigmaAdapter(BaseAdapter)
│   │   ├── translator.py            ← REFACTORED: from sigma_translator.py
│   │   └── loader.py                ← NEW: git/folder/API loading for Sigma
│   └── elastic/
│       ├── adapter.py               ← NEW: ElasticAdapter(BaseAdapter)
│       └── loader.py                ← REFACTORED: from utils.py (load_kibana_rules)
│
├── pipeline/
│   ├── ingest.py                    ← NEW: Step 1 — load catalogs via adapters
│   ├── translate.py                 ← NEW: Step 2 — normalize to canonical AST
│   ├── compare.py                   ← REFACTORED: from utils.py (find_query_overlaps)
│   ├── attack_chain.py              ← NEW: Step 4 — orchestrate attack runners
│   ├── decide.py                    ← REFACTORED: from generate_rule_decisions.py
│   └── deploy.py                    ← REFACTORED: from create_all_rules.py
│
├── attack/
│   ├── base.py                      ← NEW: Abstract AttackRunner
│   ├── sliver.py                    ← REFACTORED: from sliver_test_harness/
│   └── atomic.py                    ← NEW: Atomic Red Team runner
│
├── core/
│   ├── ast_model.py                 ← NEW: canonical RuleAST dataclass
│   ├── normalizer.py                ← REFACTORED: ECS normalization from utils.py
│   ├── scoring.py                   ← REFACTORED: scoring logic from utils.py
│   ├── config.py                    ← REFACTORED: config loader from utils.py
│   ├── theme.py                     ← REFACTORED: Streamlit CSS from utils.py
│   └── sources/
│       ├── git_source.py            ← NEW: clone/pull a git repo
│       ├── folder_source.py         ← NEW: walk a local directory
│       └── api_source.py            ← NEW: paginate a SIEM REST API
│
├── storage/
│   ├── rule_store.py                ← NEW: read/write canonical AST JSON
│   └── result_store.py             ← NEW: read/write comparison/decision outputs
│
├── catalogs/                        ← RENAMED+MERGED: rule_ast/ + complete_ruleset/
│   ├── sigma/
│   │   ├── raw/                     ← fetched source rules
│   │   └── ast/                     ← normalized AST JSON files
│   └── elastic/
│       ├── raw/
│       └── ast/
│
├── output/                          ← NEW: pipeline outputs (git-ignorable)
│   ├── overlaps/
│   ├── unique/                      ← rules to add to SIEM
│   ├── alerts/
│   └── reports/
│
├── ui/
│   ├── dashboard.py                 ← REFACTORED: Streamlit entry point
│   └── pages/
│       ├── home.py                  ← REFACTORED
│       ├── comparison.py            ← REFACTORED
│       ├── catalogs.py              ← NEW: replaces sigma_rules.py + kibana_rules.py
│       ├── scoring.py               ← REFACTORED
│       ├── attack_chain.py          ← REFACTORED: from sliver_harness.py
│       └── deploy_preview.py        ← NEW: review + deploy unique rules
│
├── scripts/                         ← KEPT: audit/ops scripts unchanged
│
├── cli.py                           ← NEW: main CLI entry point
├── config.yaml                      ← KEPT
├── requirements.txt                 ← UPDATED
├── Dockerfile                       ← UPDATED
├── docker-compose.yml               ← UPDATED
└── README.md                        ← UPDATED
```

### Files Removed / Replaced

| Old file | Fate |
|----------|------|
| `utils.py` | Split into `core/` modules |
| `sigma_translator.py` | → `adapters/sigma/translator.py` |
| `create_all_rules.py` | → `pipeline/deploy.py` |
| `create_rules_elastic.py` | → `pipeline/deploy.py` (merged) |
| `generate_rule_decisions.py` | → `pipeline/decide.py` |
| `_build_complete_ruleset.py` | → merged into `pipeline/decide.py` |
| `test_eql_rules.py` | → `pipeline/translate.py` (validation step) |
| `dashboard.py` | → `ui/dashboard.py` |
| `pages/` | → `ui/pages/` |
| `pages/sigma_rules.py` | → `ui/pages/catalogs.py` (combined) |
| `pages/kibana_rules.py` | → `ui/pages/catalogs.py` (combined) |
| `pages/sliver_harness.py` | → `ui/pages/attack_chain.py` |
| `rule_ast/` | → `catalogs/*/ast/` |
| `complete_ruleset/` | → `output/unique/` |
| `sliver_test_harness/` | → `attack/sliver.py` + scenarios inline |

---

## Adapter Interface

Every catalog adapter implements `BaseAdapter`:

```python
from abc import ABC, abstractmethod
from core.ast_model import RuleAST, ValidationResult

class BaseAdapter(ABC):
    name: str          # catalog identifier, e.g. "sigma"
    source_type: str   # "git" | "folder" | "api"

    @abstractmethod
    def load(self) -> list[dict]:
        """Fetch raw rules from source (git/folder/api). Returns raw dicts."""

    @abstractmethod
    def parse(self, raw: dict) -> RuleAST:
        """Convert a raw rule dict to canonical RuleAST."""

    @abstractmethod
    def translate(self, ast: RuleAST) -> RuleAST:
        """Normalize fields/query to ECS. Returns updated AST."""

    def validate(self, ast: RuleAST) -> ValidationResult:
        """Syntax-check the translated query. Default: no-op (returns valid)."""
        return ValidationResult(valid=True)

    def deploy(self, ast: RuleAST, client) -> bool:
        """Push a rule to the SIEM. Optional — adapters that don't support it raise NotImplementedError."""
        raise NotImplementedError
```

**Input source helpers** (shared across adapters, in `core/sources/`):
- `GitSource(url, ref, local_path)` — clone/pull, return local path
- `FolderSource(path, glob_pattern)` — walk directory, yield file paths
- `ApiSource(base_url, auth, paginate)` — paginate REST API, yield raw rule dicts

---

## Canonical RuleAST

All catalog-specific rule formats are normalized to this dataclass before comparison:

```python
@dataclass
class RuleAST:
    id: str                       # stable UUID (generated on first parse)
    catalog: str                  # "sigma" | "elastic" | "splunk" | ...
    name: str
    description: str
    severity: str                 # "critical" | "high" | "medium" | "low"
    mitre_techniques: list[str]   # ["attack.t1059.001", ...]
    event_categories: list[str]   # ["process", "network", ...]
    conditions: list[Condition]   # normalized ECS field conditions
    raw_query: str                # original query string (unchanged)
    language: str                 # "eql" | "kuery" | "esql" | "sigma" | ...
    translated_query: str | None  # ECS-normalized query (set by translate step)
    source_path: str              # original file path or API endpoint
    metadata: dict                # catalog-specific extras (tags, author, etc.)
```

Existing `rule_ast/sigma/` and `rule_ast/elastic/` JSON files will be migrated to this schema as part of the refactor. Migration is a one-time script.

---

## Pipeline & CLI

### CLI Commands

```bash
# Ingest raw rules from any source
dksec ingest --catalog sigma  --source git    --url https://github.com/SigmaHQ/sigma
dksec ingest --catalog elastic --source api   --config config.yaml
dksec ingest --catalog sigma  --source folder --path ./my-sigma-rules

# Translate to ECS-normalized AST
dksec translate --catalog sigma

# Deploy ALL rules from both catalogs to SIEM for attack chain testing
dksec deploy --mode test --a sigma --b elastic --target elastic

# Run attack chain (both catalogs must be deployed in SIEM first)
dksec attack --framework sliver
dksec attack --framework atomic
dksec attack --framework both

# Compare two catalogs (uses logic + alert data if available)
dksec compare --a sigma --b elastic --threshold 0.15

# Generate ADD/KEEP/SKIP decisions
dksec decide --a sigma --b elastic

# Deploy only the unique (non-overlapping) rules permanently
dksec deploy --mode permanent --catalog sigma --target elastic
dksec deploy --mode permanent --catalog sigma --target elastic --dry-run

# Full pipeline end-to-end
dksec run-all --a sigma --b elastic
```

### Pipeline Step Contracts

The pipeline has two distinct deploy steps:
- **Step 3 (test deploy):** Load only the *external* catalog's rules (e.g. Sigma — the ones NOT already in the SIEM) into the SIEM temporarily, tagged `dksec-test`. The existing SIEM rules are already present. This gives the attack chain a full picture: existing rules + candidate new rules firing side by side.
- **Step 6 (permanent deploy):** After comparison, push only the confirmed `output/unique/` rules to the SIEM permanently, then clean up `dksec-test` tagged rules.

| Step | Input | Output location |
|------|-------|----------------|
| `ingest` | Source config per catalog | `catalogs/<name>/raw/` |
| `translate` | `catalogs/<name>/raw/` | `catalogs/<name>/ast/` |
| `deploy --mode test` | External catalog AST + SIEM config | Candidate rules loaded in SIEM (tagged `dksec-test`) |
| `attack` | Attack config + SIEM creds | `output/alerts/` (which rules fired per scenario) |
| `compare` | Two AST sets + `output/alerts/` (optional) | `output/overlaps/`, `output/unique/` |
| `decide` | Overlaps | `output/reports/decisions.json` |
| `deploy --mode permanent` | `output/unique/` + SIEM config | Rules permanently created; `dksec-test` rules removed |

The `dksec-test` tag on test-deployed rules makes them easy to identify and clean up. The `deploy` command accepts `--mode test` or `--mode permanent`.

**Fallback (logic-only mode):** If the attack chain cannot be fired (no SIEM access, no lab environment), `compare` runs on logic alone using the Jaccard signal. This is the redundant path — less precise but always available. The `--skip-attack` flag on `run-all` activates this mode explicitly.

### Comparison Logic (catalog-agnostic)

`pipeline/compare.py` accepts both AST sets and (optionally) alert data from the attack step. It operates in two modes:

**Mode 1 — Full (logic + alerts):** Used when attack chain has run successfully.
1. **Logic-based signal:** Extract tokens (ECS fields, event categories, MITRE techniques, quoted values), pre-filter candidates by shared category or technique, compute Jaccard similarity
2. **Alert-based signal:** Rules that fired on the same attack scenario are marked as alert-confirmed overlaps
3. **Merge:** A pair is an overlap if EITHER signal confirms it — this catches rules that look different in logic but produce duplicate alerts, and vice versa
4. Rules confirmed unique by BOTH signals → `output/unique/`

**Mode 2 — Logic-only fallback:** Used when `output/alerts/` is absent (attack chain not run, or `--skip-attack` flag set).
1. Same Jaccard comparison as above, no alert overlay
2. Less precise — some false positives possible (rules may look similar but cover different attacks), but always available without a live SIEM
3. Results are labelled `confidence: logic-only` in the output to distinguish them from alert-confirmed results

---

## Attack Chain Integration

`attack/base.py` defines `AttackRunner`:

```python
class AttackRunner(ABC):
    @abstractmethod
    def run_scenario(self, scenario: AttackScenario) -> ScenarioResult:
        """Execute a MITRE ATT&CK scenario and return which rules fired."""
    
    @abstractmethod
    def list_scenarios(self) -> list[AttackScenario]:
        """Return available test scenarios."""
```

- `attack/sliver.py` — `SliverRunner(AttackRunner)`: wraps existing sliver_test_harness logic
- `attack/atomic.py` — `AtomicRunner(AttackRunner)`: runs Atomic Red Team tests via local invoke or API

Both runners return `ScenarioResult` with:
- which MITRE techniques were exercised
- which SIEM rules fired (matched by rule ID or name)
- raw alert counts

`pipeline/attack_chain.py` orchestrates one or more runners, collects results, and writes `output/alerts/` in a format that `pipeline/compare.py` can read.

---

## Streamlit UI (Read-Only)

### Page Structure

| Page | Purpose |
|------|---------|
| 🏠 Overview | Headline metrics across all loaded catalogs, pipeline run status |
| 📊 Comparison | Overlap/unique analysis — catalog picker at top, not hardcoded |
| 📋 Catalogs | Browse any loaded catalog's rules (replaces separate sigma/elastic pages) |
| 🎯 Scoring | Rule scoring & prioritization |
| ⚔️ Attack Chain | Test run status, Sliver + Atomic, MITRE coverage map |
| 🚀 Deploy Preview | Review `output/unique/` rules, one-click deploy via `dksec deploy` |

### Key UI Principles

- **Catalog-agnostic**: all pages use a catalog picker; nothing is hardcoded to Sigma or Elastic
- **Read-only by default**: UI reads from `catalogs/` and `output/`; the Deploy Preview page is the only place that can trigger a write action (via `dksec deploy` subprocess)
- **Theme**: GitHub Dark (unchanged from current)
- **Deployment target**: `dksec.kaspergissel.dk` subdomain via Docker

---

## Data Flow (End-to-End)

```
[Source A: SigmaHQ git repo]   [Source B: Elastic Kibana API]
           │                              │
           ▼                              ▼
    adapters/sigma/               adapters/elastic/
    loader.py (git clone)         loader.py (API paginate)
           │                              │
           ▼                              ▼
    catalogs/sigma/raw/           catalogs/elastic/raw/
           │                              │
           ▼                              ▼
  pipeline/translate.py         pipeline/translate.py
  (Sigma → ECS via pySigma)     (already ECS, normalize tags)
           │                              │
           ▼                              ▼
    catalogs/sigma/ast/           catalogs/elastic/ast/
           │                              │
           └──────────┬───────────────────┘
                      ▼
           pipeline/deploy.py (--mode test)
           Deploy ALL rules from both catalogs
           to SIEM, tagged "dksec-test"
                      │
                      ▼
           pipeline/attack_chain.py
           (run Sliver / Atomic against full
            combined ruleset in SIEM)
                      │
                      ▼
              output/alerts/
       (which rules fired per scenario,
        from both catalogs combined)
                      │
       ┌──────────────┘
       │
       ▼
  pipeline/compare.py
  ┌─ Signal 1: Jaccard on RuleAST tokens (logic-based)
  └─ Signal 2: alert co-firing from output/alerts/ (empirical)
  → overlap = rule pair confirmed by EITHER signal
       │
       ├─────────────────────┐
       ▼                     ▼
output/overlaps/       output/unique/
(matched pairs)        (rules with NO overlap
                        in logic OR alerts —
                        these are the gaps to fill)
       │
       ▼
  pipeline/decide.py
  (ADD / KEEP / SKIP per rule)
       │
       ▼
output/reports/decisions.json
       │
       ▼
  pipeline/deploy.py (--mode permanent)
  (push output/unique/ rules to SIEM permanently)
       │
       ▼
   [Elastic SIEM]

   ──────────────────
   ui/dashboard.py reads:
     catalogs/*/ast/     → browse rules
     output/overlaps/    → comparison page
     output/unique/      → deploy preview
     output/alerts/      → attack chain page
     output/reports/     → scoring, decisions
```

---

## Error Handling

- Each pipeline step logs to a structured JSON log file under `output/logs/`
- Adapter `translate()` failures are caught and written to `catalogs/<name>/failed/` (mirrors current `sigma_rules/failed/`)
- CLI exits with non-zero code on step failure; `run-all` stops on first step failure by default (`--continue-on-error` flag overrides)
- UI shows last-run status per step on the Overview page (read from `output/logs/`)

---

## Testing Strategy

- Unit tests for `core/` modules (normalizer, scoring, AST model)
- Adapter unit tests with fixture rule files (no live API needed)
- Integration test: `dksec run-all` with a small fixture dataset (10 Sigma + 10 Elastic rules)
- Existing `test_eql_rules.py` logic moved into `pipeline/translate.py` validation step

---

## What Does NOT Change

- Jaccard similarity algorithm (same math, just moved to `pipeline/compare.py`)
- Scoring formula (moved to `core/scoring.py`, unchanged)
- ECS field normalization logic (moved to `core/normalizer.py`, unchanged)
- GitHub Dark Streamlit theme
- `config.yaml` structure (extended for multi-catalog, backward-compatible)
- `scripts/` audit/ops scripts
- Secret scanning setup (Gitleaks, pre-commit)

---

## Out of Scope

- Real-time streaming ingestion (batch only)
- Multi-user access control on the UI
- Rule versioning / audit trail beyond file-based git history
- Support for non-ECS SIEM targets in v1 (e.g. Splunk SPL output — adapter interface supports it, implementation comes later)
