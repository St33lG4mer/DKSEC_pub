#!/usr/bin/env python3
"""Shared utilities for the DKSEC multi-page dashboard."""

import base64
import json
import math
import re
import time
from pathlib import Path

import pandas as pd
import requests
import streamlit as st
import yaml

# ---------------------------------------------------------------------------
# Paths & Constants
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).parent
TRANSLATED_DIR = BASE_DIR / "sigma_rules" / "translated"
SIGMA_ROOT = BASE_DIR / "sigma_rules"
SIGMA_AST_DIR = BASE_DIR / "rule_ast" / "sigma"
ELASTIC_AST_DIR = BASE_DIR / "rule_ast" / "elastic"
COMPLETE_SIGMA_DIR = BASE_DIR / "complete_ruleset" / "sigma"
COMPLETE_ELASTIC_DIR = BASE_DIR / "complete_ruleset" / "elastic"
RULE_DECISIONS_FILE = BASE_DIR / "rule_ast" / "rule_decisions.md"
FAILURES_FILE = BASE_DIR / "eql_validation_failures.json"
RULES_CACHE_FILE = BASE_DIR / ".kibana_rules_cache.json"
ALERTS_CACHE_FILE = BASE_DIR / ".alerts_cache.json"

EXCLUDE_PATH_FRAGMENTS = ["bitbucket", "opencanary"]

_SEVERITY_MAP = {
    "critical":      ("critical", 99),
    "high":          ("high",     73),
    "medium":        ("medium",   47),
    "low":           ("low",      21),
    "informational": ("low",      21),
}

SEV_COLORS = {
    "critical": "#f85149",
    "high":     "#d29922",
    "medium":   "#58a6ff",
    "low":      "#3fb950",
    "?":        "#8b949e",
}

ALERTS_CACHE_TTL = 300  # seconds

# ---------------------------------------------------------------------------
# Theme / CSS
# ---------------------------------------------------------------------------
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
/* Metric card grid row */
.metric-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    margin-bottom: 0;
}
/* Metric cards */
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
/* Section headers */
.section-header {
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: #8b949e;
    padding-bottom: 6px;
    border-bottom: 1px solid #21262d;
    margin: 24px 0 14px;
}
/* Coverage pills */
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
/* Dataframe tweaks */
[data-testid="stDataFrame"] { border: 1px solid #30363d; border-radius: 8px; }
/* Sidebar nav links */
[data-testid="stSidebarNav"] a {
    color: #8b949e !important;
    font-size: 0.85rem;
}
[data-testid="stSidebarNav"] a:hover,
[data-testid="stSidebarNav"] a[aria-selected="true"] {
    color: #e6edf3 !important;
    background: #21262d !important;
}
/* Status badge */
.status-badge { display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:20px;font-size:0.75rem;font-weight:600; }
.status-disconnected { background:#2d1a1a;color:#f85149;border:1px solid #5a1a1a; }
.status-connected    { background:#0d2a1a;color:#3fb950;border:1px solid #1a5a30; }
/* Muted placeholder card */
.metric-card-muted { background:#0d1117;border:1px solid #21262d;border-radius:10px;padding:20px 22px 16px;text-align:center;opacity:0.55; }
.metric-card-muted .mc-label { font-size:0.70rem;color:#484f58;text-transform:uppercase;letter-spacing:0.10em;margin-bottom:8px; }
.metric-card-muted .mc-value { font-size:2.4rem;font-weight:700;color:#484f58;line-height:1.1; }
.metric-card-muted .mc-sub   { font-size:0.78rem;color:#30363d;margin-top:6px; }
</style>
"""


def apply_theme() -> None:
    st.markdown(THEME_CSS, unsafe_allow_html=True)


def metric_card_html(
    label: str, value: str, sub: str = "", color: str = "#e6edf3"
) -> str:
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
    """SVG donut chart inside a metric-card div — matches card height exactly."""
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
    bg  = f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#21262d" stroke-width="{sw}" />'
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


# ---------------------------------------------------------------------------
# Config / Auth
# ---------------------------------------------------------------------------

_CONFIG_DEFAULTS = {
    "kibana": {"url": ""},
    "elasticsearch": {"host": "", "user": "", "password": ""},
}


@st.cache_data
def load_config() -> dict:
    # 1. Streamlit Cloud secrets (set via the app's Secrets UI)
    try:
        secrets = st.secrets
        if "kibana" in secrets or "elasticsearch" in secrets:
            return {
                "kibana": dict(secrets.get("kibana", {})),
                "elasticsearch": dict(secrets.get("elasticsearch", {})),
            }
    except Exception:
        pass

    # 2. Local config.yaml
    cfg_path = BASE_DIR / "config.yaml"
    if cfg_path.exists():
        with open(cfg_path, encoding="utf-8") as f:
            return yaml.safe_load(f)

    # 3. No config — return safe defaults so the app can still render
    return _CONFIG_DEFAULTS


def kibana_headers(user: str, password: str) -> dict:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {
        "Authorization": f"Basic {token}",
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
    }


def es_session(user: str, password: str) -> requests.Session:
    s = requests.Session()
    s.auth = (user, password)
    s.headers.update({"Content-Type": "application/json"})
    return s


# ---------------------------------------------------------------------------
# Sigma rules
# ---------------------------------------------------------------------------

def _risk_to_severity(risk: int) -> str:
    if risk >= 99:
        return "critical"
    if risk >= 73:
        return "high"
    if risk >= 47:
        return "medium"
    if risk >= 21:
        return "low"
    return "informational"


@st.cache_data(show_spinner="Loading Sigma rules…")
def load_sigma_rules() -> list[dict]:
    rules = []
    for json_path in sorted(SIGMA_AST_DIR.glob("*.json")):
        name = json_path.stem
        if any(f in name for f in EXCLUDE_PATH_FRAGMENTS):
            continue
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
        except Exception:
            continue

        sigma_rel = data.get("sigma_path", "")
        meta: dict = {}
        if sigma_rel:
            yaml_path = SIGMA_ROOT / Path(sigma_rel).with_suffix(".yml")
            if yaml_path.exists():
                try:
                    meta = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
                except Exception:
                    pass

        query = data.get("raw_query", "")
        level = (meta.get("level") or "medium").lower()
        severity, risk_score = _SEVERITY_MAP.get(level, ("medium", 47))
        raw_tags = meta.get("tags") or []
        mitre_techniques = [
            t for t in raw_tags
            if isinstance(t, str) and re.match(r"attack\.t\d+", t, re.I)
        ]
        mitre_tactics = [
            t for t in raw_tags
            if isinstance(t, str)
            and t.startswith("attack.")
            and not re.match(r"attack\.t\d+", t, re.I)
        ]
        rules.append({
            "name":       f"(SIGMA) {meta.get('title') or name}",
            "title":      meta.get("title") or name,
            "rule_id":    str(meta.get("id") or name),
            "severity":   severity,
            "risk_score": risk_score,
            "query":      query,
            "techniques": mitre_techniques,
            "tactics":    mitre_tactics,
            "status":     meta.get("status", "unknown"),
            "path":       str(json_path),
        })
    return rules


# ---------------------------------------------------------------------------
# Complete ruleset loaders (complete_ruleset/ — curated deployment set)
# ---------------------------------------------------------------------------

def _normalize_elastic_mitre_tag(tag: str) -> str | None:
    m = re.match(r"^Tactic:\s*(.+)$", tag, re.I)
    if m:
        return "attack." + m.group(1).strip().lower().replace(" ", "-")
    m = re.match(r"^(?:Technique|Subtechnique):.*\(([Tt]\d+(?:\.\d+)?)\)\s*$", tag)
    if m:
        return "attack." + m.group(1).lower()
    return None


@st.cache_data(show_spinner="Loading complete Sigma ruleset…")
def load_complete_sigma_rules() -> list[dict]:
    rules = []
    for json_path in sorted(COMPLETE_SIGMA_DIR.glob("*.json")):
        name = json_path.stem
        if any(f in name for f in EXCLUDE_PATH_FRAGMENTS):
            continue
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        sigma_rel = data.get("sigma_path", "")
        meta: dict = {}
        if sigma_rel:
            yaml_path = SIGMA_ROOT / Path(sigma_rel).with_suffix(".yml")
            if yaml_path.exists():
                try:
                    meta = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
                except Exception:
                    pass
        level = (meta.get("level") or "medium").lower()
        severity, risk_score = _SEVERITY_MAP.get(level, ("medium", 47))
        raw_tags = meta.get("tags") or []
        mitre_techniques = [t for t in raw_tags if isinstance(t, str) and re.match(r"attack\.t\d+", t, re.I)]
        mitre_tactics    = [t for t in raw_tags if isinstance(t, str) and t.startswith("attack.") and not re.match(r"attack\.t\d+", t, re.I)]
        rules.append({
            "name":       f"(SIGMA) {meta.get('title') or name}",
            "title":      meta.get("title") or name,
            "rule_id":    str(meta.get("id") or name),
            "severity":   severity,
            "risk_score": risk_score,
            "query":      data.get("raw_query", ""),
            "category":   data.get("category", "any"),
            "techniques": mitre_techniques,
            "tactics":    mitre_tactics,
            "status":     meta.get("status", "unknown"),
            "path":       str(json_path),
        })
    return rules


@st.cache_data(show_spinner="Loading complete Elastic ruleset…")
def load_complete_elastic_rules() -> list[dict]:
    rules = []
    for json_path in sorted(COMPLETE_ELASTIC_DIR.glob("*.json")):
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        risk = data.get("risk_score", 47)
        normalized_tags = []
        for t in (data.get("tags") or []):
            norm = _normalize_elastic_mitre_tag(t)
            normalized_tags.append(norm if norm else t)
        rules.append({
            "name":       data.get("name", json_path.stem),
            "rule_id":    data.get("slug", json_path.stem),
            "id":         data.get("slug", json_path.stem),
            "type":       data.get("language", "eql"),
            "severity":   _risk_to_severity(risk),
            "risk_score": risk,
            "enabled":    True,
            "tags":       normalized_tags,
            "query":      data.get("raw_query", ""),
            "category":   data.get("category", "any"),
        })
    return rules


# ---------------------------------------------------------------------------
# Rule decisions (rule_ast/rule_decisions.md)
# ---------------------------------------------------------------------------

@st.cache_data(show_spinner="Loading rule decisions…")
def load_rule_decisions() -> dict:
    """
    Parse rule_ast/rule_decisions.md into structured dicts.

    Returns:
        {
          "delete":  [{"name", "slug", "risk", "replaced_by": [str]}],
          "keep":    [{"slug", "name", "note"}],
          "add":     [{"name"}],
          "skip":    [{"name"}],
          "manual":  [{"name"}],
          "summary": {"delete": int, "keep": int, "add": int, "skip": int, "manual": int},
        }
    """
    if not RULE_DECISIONS_FILE.exists():
        return {"delete": [], "keep": [], "add": [], "skip": [], "manual": [],
                "summary": {}}

    result: dict = {"delete": [], "keep": [], "add": [], "skip": [], "manual": []}
    section = None

    for line in RULE_DECISIONS_FILE.read_text(encoding="utf-8").splitlines():
        if line.startswith("## 1."):
            section = "delete"
        elif line.startswith("## 2."):
            section = "keep"
        elif line.startswith("## 3."):
            section = "add"
        elif line.startswith("## 4."):
            section = "skip"
        elif line.startswith("## 5."):
            section = "manual"

        if section == "delete":
            # | Elastic Rule | `slug` | risk | `sigma1`, `sigma2` |
            if line.startswith("|") and not line.startswith("| Elastic") and "---" not in line:
                parts = [p.strip() for p in line.split("|")[1:-1]]
                if len(parts) >= 4:
                    slugs = re.findall(r"`([^`]+)`", parts[1])
                    slug = slugs[0] if slugs else parts[1]
                    try:
                        risk = int(parts[2])
                    except ValueError:
                        risk = 0
                    replaced_by = re.findall(r"`([^`]+)`", parts[3])
                    result["delete"].append({
                        "name": parts[0],
                        "slug": slug,
                        "risk": risk,
                        "replaced_by": replaced_by,
                    })

        elif section == "keep":
            # - `slug` — Name *(optional note)*
            if line.startswith("- "):
                m = re.match(r"^- `([^`]+)` — (.+?)(?:\s*\*\(([^)]+)\)\*)?$", line)
                if m:
                    result["keep"].append({
                        "slug": m.group(1),
                        "name": m.group(2).strip(),
                        "note": m.group(3) or "",
                    })

        elif section in ("add", "skip", "manual"):
            # - `Rule Name`
            if line.startswith("- "):
                m = re.match(r"^- `([^`]+)`", line)
                if m:
                    result[section].append({"name": m.group(1)})

    result["summary"] = {k: len(v) for k, v in result.items() if k != "summary"}
    return result


# ---------------------------------------------------------------------------
# EQL validation failures
# ---------------------------------------------------------------------------

@st.cache_data(show_spinner="Loading validation failures…")
def load_failures() -> dict[str, str]:
    if not FAILURES_FILE.exists():
        return {}
    try:
        items = json.loads(FAILURES_FILE.read_text(encoding="utf-8"))
        return {Path(i["file"]).stem: i.get("reason", "unknown") for i in items}
    except Exception:
        return {}


def categorize_failure(reason: str) -> tuple[str, str]:
    """Return (human_category, affected_fields_str)."""
    if not reason:
        return "Unknown", ""
    bracketed = re.findall(r"\[([^\]]+)\]", reason)
    ecs_fields = [f for f in bracketed if "." in f]
    field_str = ", ".join(ecs_fields[:4]) or ", ".join(bracketed[:3])
    r = reason.lower()
    if "unknown column" in r or "unknown field" in r:
        return "Unknown field", field_str
    if "token recognition error" in r:
        return "Regex syntax error", ""
    if "must be [boolean]" in r:
        return "Type error — boolean expected", field_str
    if "must be [string]" in r:
        return "Type error — string expected", field_str
    if "type [object]" in r and "only its subfields" in r:
        return "Object field — use subfield", field_str
    if "type [integer]" in r:
        return "Integer/string mismatch", field_str
    if "condition expression" in r:
        return "Non-boolean condition", ""
    if "found" in r and "problem" in r:
        return "Multiple EQL errors", field_str
    return "Other EQL error", reason.splitlines()[0][:60]


# ---------------------------------------------------------------------------
# Kibana rules
# ---------------------------------------------------------------------------

@st.cache_data(show_spinner="Loading detection rules…")
def load_kibana_rules(kibana_url: str, user: str, password: str) -> list[dict]:
    # Live Kibana cache takes priority when present
    if RULES_CACHE_FILE.exists():
        try:
            return json.loads(RULES_CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass

    # Fall back to local rule_ast files
    rules: list[dict] = []

    for json_path in sorted(ELASTIC_AST_DIR.glob("*.json")):
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        risk = data.get("risk_score", 47)
        rules.append({
            "name":       data.get("name", json_path.stem),
            "rule_id":    data.get("slug", json_path.stem),
            "id":         data.get("slug", json_path.stem),
            "type":       data.get("language", "eql"),
            "severity":   _risk_to_severity(risk),
            "risk_score": risk,
            "enabled":    True,
            "tags":       data.get("tags") or [],
            "query":      data.get("raw_query", ""),
        })

    # Include sigma rules tagged as SIGMA so existing page logic works
    for sr in load_sigma_rules():
        rules.append({
            "name":       sr["name"],
            "rule_id":    sr["rule_id"],
            "id":         sr["rule_id"],
            "type":       "eql",
            "severity":   sr["severity"],
            "risk_score": sr["risk_score"],
            "enabled":    True,
            "tags":       ["SIGMA"] + sr["tactics"] + sr["techniques"],
            "query":      sr["query"],
        })

    return rules


@st.cache_data(show_spinner=False)
def complete_sigma_stems() -> frozenset:
    """Return stems of all JSON files in complete_ruleset/sigma/ (ready-to-deploy set)."""
    return frozenset(f.stem for f in COMPLETE_SIGMA_DIR.glob("*.json"))


def refresh_kibana_rules(kibana_url: str, user: str, password: str) -> list[dict]:
    headers = kibana_headers(user, password)
    rules, page, per_page = [], 1, 500
    while True:
        for attempt in range(5):
            resp = requests.get(
                f"{kibana_url}/api/detection_engine/rules/_find",
                headers=headers,
                params={"page": page, "per_page": per_page},
                timeout=30,
            )
            if resp.status_code in (429, 500):
                time.sleep(2 ** attempt)
                continue
            break
        if resp.status_code in (429, 500):
            st.warning(f"Kibana fetch stopped after retries (status {resp.status_code}).")
            break
        if resp.status_code != 200:
            raise RuntimeError(f"Kibana API error {resp.status_code}: {resp.text[:200]}")
        data = resp.json()
        batch = data.get("data", [])
        rules.extend(batch)
        if len(rules) >= data.get("total", 0) or not batch:
            break
        page += 1
    if rules:
        RULES_CACHE_FILE.write_text(json.dumps(rules), encoding="utf-8")
    return rules


# ---------------------------------------------------------------------------
# Live alert data — last 24 h
# ---------------------------------------------------------------------------

def fetch_alerts_24h(es_host: str, user: str, password: str) -> dict:
    """Query .alerts-security.alerts-default for last 24h. File-cached 5 min."""
    if not es_host:
        return {
            "total": 0,
            "by_severity": {},
            "sigma":   {"total": 0, "by_severity": {}, "top_rules": []},
            "elastic": {"total": 0, "by_severity": {}, "top_rules": []},
            "timeline": [],
            "error": "No Elasticsearch host configured.",
        }

    if ALERTS_CACHE_FILE.exists():
        age = time.time() - ALERTS_CACHE_FILE.stat().st_mtime
        if age < ALERTS_CACHE_TTL:
            try:
                return json.loads(ALERTS_CACHE_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass

    body = {
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
        "size": 0,
        "aggs": {
            "by_severity": {
                "terms": {"field": "kibana.alert.severity", "size": 10}
            },
            "sigma_alerts": {
                "filter": {"term": {"kibana.alert.rule.tags": "SIGMA"}},
                "aggs": {
                    "by_severity": {"terms": {"field": "kibana.alert.severity", "size": 10}},
                    "top_rules":   {"terms": {"field": "kibana.alert.rule.name", "size": 20}},
                },
            },
            "elastic_alerts": {
                "filter": {
                    "bool": {"must_not": {"term": {"kibana.alert.rule.tags": "SIGMA"}}}
                },
                "aggs": {
                    "by_severity": {"terms": {"field": "kibana.alert.severity", "size": 10}},
                    "top_rules":   {"terms": {"field": "kibana.alert.rule.name", "size": 20}},
                },
            },
            "timeline": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "1h",
                    "extended_bounds": {"min": "now-24h", "max": "now"},
                }
            },
        },
    }

    _empty = {
        "total": 0,
        "by_severity": {},
        "sigma":   {"total": 0, "by_severity": {}, "top_rules": []},
        "elastic": {"total": 0, "by_severity": {}, "top_rules": []},
        "timeline": [],
        "error": None,
    }

    try:
        sess = es_session(user, password)
        resp = sess.post(
            f"{es_host}/.alerts-security.alerts-default/_search",
            json=body,
            params={"ignore_unavailable": "true"},
            timeout=15,
        )
        resp.raise_for_status()
        raw = resp.json()
        aggs = raw.get("aggs", raw.get("aggregations", {}))

        def _bkts(key: str, nested: str | None = None) -> list[dict]:
            node = aggs.get(key, {})
            if nested:
                node = node.get(nested, {})
            return node.get("buckets", [])

        result = {
            "total": raw.get("hits", {}).get("total", {}).get("value", 0),
            "by_severity": {b["key"]: b["doc_count"] for b in _bkts("by_severity")},
            "sigma": {
                "total": aggs.get("sigma_alerts", {}).get("doc_count", 0),
                "by_severity": {
                    b["key"]: b["doc_count"] for b in _bkts("sigma_alerts", "by_severity")
                },
                "top_rules": [
                    {"rule": b["key"], "count": b["doc_count"]}
                    for b in _bkts("sigma_alerts", "top_rules")
                ],
            },
            "elastic": {
                "total": aggs.get("elastic_alerts", {}).get("doc_count", 0),
                "by_severity": {
                    b["key"]: b["doc_count"] for b in _bkts("elastic_alerts", "by_severity")
                },
                "top_rules": [
                    {"rule": b["key"], "count": b["doc_count"]}
                    for b in _bkts("elastic_alerts", "top_rules")
                ],
            },
            "timeline": [
                {"hour": b.get("key_as_string", ""), "count": b["doc_count"]}
                for b in _bkts("timeline")
            ],
            "error": None,
        }
        ALERTS_CACHE_FILE.write_text(json.dumps(result), encoding="utf-8")
        return result
    except Exception as exc:
        # Sanitize: don't leak host/URL details into the UI
        short = type(exc).__name__
        status = getattr(getattr(exc, "response", None), "status_code", None)
        if status:
            short = f"HTTP {status}"
        return {**_empty, "error": f"Elasticsearch unreachable ({short})."}


# ---------------------------------------------------------------------------
# Query token extraction & Jaccard similarity
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
    """Extract ECS fields, event categories, and meaningful quoted values."""
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
    return frozenset(t for t in tokens if t.startswith("@cat:"))


def jaccard(a: frozenset, b: frozenset) -> float:
    if not a and not b:
        return 0.0
    union = len(a | b)
    return len(a & b) / union if union else 0.0


# ---------------------------------------------------------------------------
# Query-logic overlap detection
# ---------------------------------------------------------------------------

@st.cache_data(show_spinner="Analysing rule logic…")
def find_query_overlaps(
    sigma_rules: list[dict],
    kibana_rules: list[dict],
    query_threshold: float,
) -> tuple[list[dict], dict]:
    """
    Compare Sigma vs Elastic rules by query-token Jaccard similarity.
    Only pairs rules that share at least one event category.
    Sigma-only categories are flagged as unique coverage and excluded from pairing.
    Returns (overlaps, coverage_map).
    """
    elastic_only = [r for r in kibana_rules if "SIGMA" not in (r.get("tags") or [])]

    # Pre-compute tokens for sigma rules
    # Augment EQL-extracted categories with the stored 'category' field.
    # Sigma rules translate to 'any where ...' EQL, so the regex finds no category;
    # the JSON 'category' field is the authoritative source.
    _SKIP_CATS = frozenset({"any", ""})
    sigma_prep = []
    for sr in sigma_rules:
        toks = extract_eql_tokens(sr["query"])
        cats = get_event_categories(toks)
        stored = (sr.get("category") or "").lower()
        if stored and stored not in _SKIP_CATS:
            cats = cats | frozenset({f"@cat:{stored}"})
        mitre = frozenset(t.lower() for t in sr.get("techniques", []))
        sigma_prep.append((sr, toks, cats, mitre))

    # Pre-compute tokens for elastic rules (same augmentation)
    elastic_prep = []
    for er in elastic_only:
        q = er.get("query") or er.get("name") or ""
        toks = extract_eql_tokens(q)
        cats = get_event_categories(toks)
        stored = (er.get("category") or "").lower()
        if stored and stored not in _SKIP_CATS | frozenset({"info"}):
            cats = cats | frozenset({f"@cat:{stored}"})
        er_mitre = frozenset(
            t.lower() for t in (er.get("tags") or [])
            if re.match(r"attack\.t\d+", t, re.I)
        )
        elastic_prep.append((er, toks, cats, er_mitre))

    # Build coverage map
    all_sigma_cats: set[str] = set()
    for _, _, cats, _ in sigma_prep:
        all_sigma_cats |= cats

    all_elastic_cats: set[str] = set()
    for _, _, cats, _ in elastic_prep:
        all_elastic_cats |= cats

    sigma_only_cats = all_sigma_cats - all_elastic_cats
    elastic_only_cats = all_elastic_cats - all_sigma_cats
    shared_cats = all_sigma_cats & all_elastic_cats

    coverage = {
        "sigma_only":   sorted(c[5:] for c in sigma_only_cats),
        "elastic_only": sorted(c[5:] for c in elastic_only_cats),
        "shared":       sorted(c[5:] for c in shared_cats),
    }

    # Inverted indexes for fast candidate lookup
    cat_index: dict[str, list[int]] = {}
    for idx, (_, _, cats, _) in enumerate(elastic_prep):
        for cat in cats:
            cat_index.setdefault(cat, []).append(idx)

    mitre_index: dict[str, list[int]] = {}
    for idx, (_, _, _, em) in enumerate(elastic_prep):
        for tag in em:
            mitre_index.setdefault(tag, []).append(idx)

    field_index: dict[str, list[int]] = {}
    for idx, (_, toks, _, _) in enumerate(elastic_prep):
        for tok in toks:
            if not tok.startswith("@"):
                field_index.setdefault(tok, []).append(idx)

    overlaps: list[dict] = []
    seen: set[tuple] = set()

    for sr, sr_toks, sr_cats, sr_mitre in sigma_prep:
        # Skip sigma rules whose categories are exclusively sigma-only
        if sr_cats and sr_cats.issubset(sigma_only_cats):
            continue

        effective_cats = sr_cats - sigma_only_cats
        candidates: set[int] = set()

        if effective_cats:
            for cat in effective_cats:
                for idx in cat_index.get(cat, []):
                    candidates.add(idx)
        elif not sr_cats:
            # No category detected — fall back to ECS field matching
            for tok in sr_toks:
                if not tok.startswith("@"):
                    for idx in field_index.get(tok, []):
                        candidates.add(idx)

        # Always add MITRE-matching rules
        for tag in sr_mitre:
            for idx in mitre_index.get(tag, []):
                candidates.add(idx)

        for idx in candidates:
            er, er_toks, er_cats, er_mitre = elastic_prep[idx]
            pair_key = (sr["rule_id"], er.get("rule_id", er.get("id", "")))
            if pair_key in seen:
                continue

            j = jaccard(sr_toks, er_toks)
            shared_mitre = sr_mitre & er_mitre
            if j < query_threshold and not shared_mitre:
                continue

            seen.add(pair_key)
            shared_toks = sr_toks & er_toks
            shared_fields = sorted(t for t in shared_toks if not t.startswith("@"))[:8]
            shared_cats_pair = sorted(c[5:] for c in (sr_cats & er_cats))

            overlaps.append({
                "sigma_name":     sr["name"],
                "elastic_name":   er.get("name") or "",
                "jaccard":        round(j, 3),
                "shared_fields":  ", ".join(shared_fields) or "—",
                "shared_cats":    ", ".join(shared_cats_pair) or "—",
                "shared_mitre":   ", ".join(sorted(shared_mitre)) or "—",
                "sigma_severity": sr["severity"],
                "elastic_sev":    er.get("severity", "?"),
                "sigma_fires":    0,
                "elastic_fires":  0,
                "sigma_id":       sr["rule_id"],
                "elastic_id":     er.get("rule_id", er.get("id", "")),
                "suggested_best": "SIGMA" if sr["risk_score"] >= er.get("risk_score", 0) else "Elastic",
            })

    overlaps.sort(key=lambda x: -x["jaccard"])
    return overlaps, coverage


def enrich_overlaps_with_alerts(overlaps: list[dict], alert_data: dict) -> list[dict]:
    sigma_counts = {r["rule"]: r["count"] for r in alert_data.get("sigma", {}).get("top_rules", [])}
    elastic_counts = {r["rule"]: r["count"] for r in alert_data.get("elastic", {}).get("top_rules", [])}
    enriched = []
    for o in overlaps:
        o = dict(o)
        sigma_clean = re.sub(r"^\(sigma\)\s*", "", o["sigma_name"], flags=re.I).strip()
        o["sigma_fires"] = sigma_counts.get(o["sigma_name"], sigma_counts.get(sigma_clean, 0))
        o["elastic_fires"] = elastic_counts.get(o["elastic_name"], 0)
        enriched.append(o)
    return enriched


# ---------------------------------------------------------------------------
# Rule scoring
# ---------------------------------------------------------------------------

def classify_rule(fires: int, severity: str) -> str:
    """Classify a rule as dead / noisy / valuable / active."""
    if fires == 0:
        return "dead"
    if fires >= 50 and severity in ("low", "medium"):
        return "noisy"
    if fires > 0 and severity in ("high", "critical"):
        return "valuable"
    return "active"


def compute_coverage_pct(sigma_in_set: int, total_sigma: int) -> int:
    """% of SIGMA rules in the deploy-ready complete_ruleset."""
    if total_sigma == 0:
        return 0
    return round(sigma_in_set / total_sigma * 100)


def compute_signal_ratio(alerts: dict) -> float:
    """(critical + high alerts) / total alerts as a percentage. Returns 0.0 if no data."""
    total = alerts.get("total", 0)
    if total == 0:
        return 0.0
    by_sev = alerts.get("by_severity", {})
    high_crit = by_sev.get("high", 0) + by_sev.get("critical", 0)
    return round(high_crit / total * 100, 1)


def get_critical_gaps(
    sigma_rules: list[dict],
    sigma_stems: frozenset,
    failures: dict,
) -> list[dict]:
    """Return high/critical SIGMA rules NOT in the deploy ruleset, sorted by risk score."""
    gaps = []
    for r in sigma_rules:
        if r["severity"] not in ("high", "critical"):
            continue
        stem = Path(r["path"]).stem
        if stem not in sigma_stems:
            gaps.append({
                "Name":       r["title"],
                "Severity":   r["severity"],
                "Risk Score": r["risk_score"],
                "EQL Valid":  "✅" if stem not in failures else "❌",
                "MITRE":      len(r["techniques"]),
            })
    return sorted(gaps, key=lambda x: -x["Risk Score"])


def score_rules(
    sigma_rules: list[dict],
    failures: dict,
    sigma_in_kibana: set,
    overlapping_ids: set,
    alert_counts: dict | None = None,
) -> pd.DataFrame:
    alert_counts = alert_counts or {}
    rows = []
    for r in sigma_rules:
        stem = Path(r["path"]).stem
        valid       = stem not in failures
        in_kb       = r["rule_id"] in sigma_in_kibana
        has_overlap = r["rule_id"] in overlapping_ids
        fires       = alert_counts.get(r["name"], 0)
        fire_bonus  = min(fires * 2, 20)

        score = r["risk_score"]
        score += 10 if valid else 0
        score += len(r["techniques"]) * 5
        score += 10 if in_kb else 0
        score -= 15 if has_overlap else 0
        score += fire_bonus

        rows.append({
            "Name":                r["title"],
            "Score":               score,
            "Risk Score":          r["risk_score"],
            "Severity":            r["severity"],
            "EQL Valid":           "✅" if valid else "❌",
            "In Kibana":           "✅" if in_kb else "—",
            "Unique (no overlap)": "✅" if not has_overlap else "⚠️ Overlap",
            "MITRE Techniques":    len(r["techniques"]),
            "24h Alerts":          fires,
            "Classification":      classify_rule(fires, r["severity"]),
        })
    if len(rows) > 1:
        scores = [row["Score"] for row in rows]
        min_s, max_s = min(scores), max(scores)
        rng = max_s - min_s or 1
        for row in rows:
            row["Score"] = round((row["Score"] - min_s) / rng * 100)
    return pd.DataFrame(rows).sort_values("Score", ascending=False).reset_index(drop=True)


# ---------------------------------------------------------------------------
# Full coverage report (offline — no Elastic API required)
# ---------------------------------------------------------------------------

@st.cache_data(show_spinner="Computing coverage report…")
def compute_coverage_report(
    sigma_rules: list[dict],
    elastic_rules: list[dict],
    threshold: float = 0.15,
) -> dict:
    """
    Full offline coverage analysis — compares sigma vs elastic rule inventories.

    Returns:
        overlaps                — rule pairs (sigma ↔ elastic) sharing query logic
        coverage                — {sigma_only, elastic_only, shared} event categories
        sigma_unique            — sigma rules with NO elastic equivalent (→ add to SIEM)
        elastic_unique          — elastic rules with NO sigma equivalent (gap without sigma)
        sigma_only_techniques   — MITRE techniques in sigma but not elastic
        elastic_only_techniques — MITRE techniques in elastic but not sigma
        shared_techniques       — MITRE techniques covered by both
    """
    overlaps, coverage = find_query_overlaps(sigma_rules, elastic_rules, threshold)

    sigma_ids_in_overlap   = {o["sigma_id"]   for o in overlaps}
    elastic_ids_in_overlap = {o["elastic_id"] for o in overlaps}

    elastic_only_rules = [r for r in elastic_rules if "SIGMA" not in (r.get("tags") or [])]

    sigma_unique = sorted(
        [r for r in sigma_rules if r["rule_id"] not in sigma_ids_in_overlap],
        key=lambda r: -r["risk_score"],
    )
    elastic_unique = sorted(
        [
            r for r in elastic_only_rules
            if r.get("rule_id", r.get("id", "")) not in elastic_ids_in_overlap
        ],
        key=lambda r: -r.get("risk_score", 0),
    )

    sigma_techniques: set[str] = set()
    for r in sigma_rules:
        sigma_techniques.update(t.lower() for t in r.get("techniques", []))

    elastic_techniques: set[str] = set()
    for r in elastic_only_rules:
        for t in (r.get("tags") or []):
            if isinstance(t, str) and re.match(r"attack\.t\d+", t, re.I):
                elastic_techniques.add(t.lower())

    return {
        "overlaps":                 overlaps,
        "coverage":                 coverage,
        "sigma_unique":             sigma_unique,
        "elastic_unique":           elastic_unique,
        "sigma_only_techniques":    sorted(sigma_techniques - elastic_techniques),
        "elastic_only_techniques":  sorted(elastic_techniques - sigma_techniques),
        "shared_techniques":        sorted(sigma_techniques & elastic_techniques),
    }
