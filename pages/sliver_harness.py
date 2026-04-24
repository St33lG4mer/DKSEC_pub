#!/usr/bin/env python3
"""Sliver Harness -- Windows detection rule validation via Sliver C2."""

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

from utils import (
    BASE_DIR,
    apply_theme,
    load_config,
    metric_card_html,
    metric_card_muted_html,
)

# Allow importing from sliver_test_harness/
sys.path.insert(0, str(BASE_DIR / "sliver_test_harness"))
from scenarios import SCENARIOS, SCENARIO_ORDER  # noqa: E402

apply_theme()
load_config()

# ---------------------------------------------------------------------------
# Load coverage data
# ---------------------------------------------------------------------------
COVERAGE_CSV = BASE_DIR / "sliver_test_harness" / "coverage_map.csv"
TIMELINE_HTML = BASE_DIR / "sliver_test_harness" / "attack_timeline.html"
RESULTS_DIR = BASE_DIR / "sliver_test_harness" / "results"

coverage_df = pd.DataFrame()
if COVERAGE_CSV.exists():
    coverage_df = pd.read_csv(COVERAGE_CSV)

# Pre-compute stats from coverage map
win_rules = coverage_df[coverage_df["platform"] == "windows"] if not coverage_df.empty else pd.DataFrame()
total_rules = len(coverage_df)
total_win = len(win_rules)

# Sliver bucket counts (windows only)
bucket_counts = win_rules["sliver_bucket"].value_counts().to_dict() if not win_rules.empty else {}
native_count = bucket_counts.get("native", 0)
byot_count = bucket_counts.get("byot", 0)
oos_count = bucket_counts.get("oos", 0)

# Unique MITRE techniques from scenarios
all_techniques = set()
total_steps = 0
for sc in SCENARIOS.values():
    for step in sc["steps"]:
        total_steps += 1
        if step.get("atck"):
            all_techniques.add(step["atck"])

# ---------------------------------------------------------------------------
# Page header
# ---------------------------------------------------------------------------
st.title("Sliver Harness")
st.caption("Automated Windows detection rule validation via Sliver C2.")

# ---------------------------------------------------------------------------
# Status bar
# ---------------------------------------------------------------------------
st.markdown(
    """
    <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;
                padding:12px 18px;display:flex;align-items:center;gap:12px;margin-bottom:8px">
      <span style="width:10px;height:10px;border-radius:50%;background:#f85149;display:inline-block"></span>
      <span style="color:#8b949e;font-size:0.85rem">STATUS</span>
      <span style="color:#e6edf3;font-weight:600">Disconnected</span>
      <span style="color:#30363d;margin:0 8px">|</span>
      <span style="color:#8b949e;font-size:0.85rem">SERVER</span>
      <span style="color:#e6edf3">Not configured</span>
      <span style="color:#30363d;margin:0 8px">|</span>
      <span style="color:#8b949e;font-size:0.85rem">IMPLANT</span>
      <span style="color:#e6edf3">&#8212;</span>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Connection panel
# ---------------------------------------------------------------------------
with st.expander("Configure Connection", expanded=False):
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        st.text_input("Sliver Server Host", placeholder="192.168.x.x")
    with col2:
        st.number_input("gRPC Port", value=31337, min_value=1, max_value=65535)
    with col3:
        st.text_input("Implant ID", placeholder="BRAVE_TOMCAT")
    st.button("Connect to Sliver", disabled=True)
    st.caption("Connection functionality not yet implemented.")

st.divider()

# ---------------------------------------------------------------------------
# Stats row -- CSS grid for equal-height alignment
# ---------------------------------------------------------------------------
st.markdown(
    '<div class="metric-row">'
    + metric_card_html(
        "Scenarios", str(len(SCENARIOS)),
        f"{total_steps} steps / {len(all_techniques)} MITRE techniques", "#58a6ff",
    )
    + metric_card_html(
        "Windows Rules", str(total_win),
        f"{total_rules} total across all platforms", "#3fb950",
    )
    + metric_card_html(
        "Sliver-Testable", str(native_count + byot_count),
        f"{native_count} native / {byot_count} BYOT / {oos_count} out-of-scope", "#d29922",
    )
    + metric_card_muted_html(
        "Last Run", "--", "no test runs yet",
    )
    + '</div>',
    unsafe_allow_html=True,
)

st.divider()

# ---------------------------------------------------------------------------
# Scenario overview table (from real scenarios.py)
# ---------------------------------------------------------------------------
st.markdown('<div class="section-header">Attack Scenarios</div>', unsafe_allow_html=True)

scenario_rows = []
for sid in SCENARIO_ORDER:
    sc = SCENARIOS[sid]
    steps = sc["steps"]
    techniques = sorted({s["atck"] for s in steps if s.get("atck")})
    # Count rules mapped to this scenario from coverage map
    rule_count = len(win_rules[win_rules["scenario_id"] == sid]) if not win_rules.empty else 0
    scenario_rows.append(
        {
            "Scenario": sid.replace("_", " ").title(),
            "ID": sid,
            "Steps": len(steps),
            "MITRE Techniques": ", ".join(techniques),
            "Mapped Rules": rule_count,
            "Status": "Not run",
        }
    )

sc_df = pd.DataFrame(scenario_rows)
st.dataframe(sc_df, width='stretch', height=380, hide_index=True)

st.divider()

# ---------------------------------------------------------------------------
# Platform & scenario rule breakdown
# ---------------------------------------------------------------------------
st.markdown('<div class="section-header">Coverage Breakdown</div>', unsafe_allow_html=True)

if not coverage_df.empty:
    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown("##### Platform Distribution")
        plat_counts = coverage_df["platform"].value_counts().reset_index()
        plat_counts.columns = ["Platform", "Rules"]
        st.dataframe(plat_counts, width='stretch', hide_index=True)

    with col_right:
        st.markdown("##### Windows Rules by Scenario")
        if not win_rules.empty:
            sc_counts = (
                win_rules.groupby("scenario_id")
                .agg(Total=("slug", "count"),
                     Sigma=("source", lambda x: (x == "sigma").sum()),
                     Elastic=("source", lambda x: (x == "elastic").sum()))
                .sort_values("Total", ascending=False)
                .reset_index()
            )
            sc_counts.rename(columns={"scenario_id": "Scenario"}, inplace=True)
            st.dataframe(sc_counts, width='stretch', hide_index=True, height=380)
else:
    st.info("Run `python sliver_test_harness/build_coverage_map.py` to generate the coverage map.")

st.divider()

# ---------------------------------------------------------------------------
# Scenario detail drilldown
# ---------------------------------------------------------------------------
st.markdown('<div class="section-header">Scenario Details</div>', unsafe_allow_html=True)

for sid in SCENARIO_ORDER:
    sc = SCENARIOS[sid]
    label = sid.replace("_", " ").title()
    step_count = len(sc["steps"])
    with st.expander(f"{label} - {step_count} steps", expanded=False):
        st.markdown(f"**{sc['description']}**")
        step_rows = []
        for s in sc["steps"]:
            step_rows.append({
                "Step": s["name"],
                "Kind": s["kind"],
                "ATT&CK": s.get("atck", ""),
                "Command": f"{s['command']} {' '.join(s.get('args', [])[:3])}",
            })
        st.dataframe(pd.DataFrame(step_rows), width='stretch', hide_index=True)

st.divider()

# ---------------------------------------------------------------------------
# Attack Timeline link
# ---------------------------------------------------------------------------
if TIMELINE_HTML.exists():
    st.markdown('<div class="section-header">Attack Timeline</div>', unsafe_allow_html=True)
    st.markdown(
        "Full visual timeline of all 9 scenarios with color-coded steps and MITRE ATT&CK links."
    )
    with open(TIMELINE_HTML, "r", encoding="utf-8") as f:
        st.download_button(
            "Download Attack Timeline (HTML)",
            data=f.read(),
            file_name="attack_timeline.html",
            mime="text/html",
        )

st.divider()

# ---------------------------------------------------------------------------
# Past run results
# ---------------------------------------------------------------------------
if RESULTS_DIR.exists():
    result_files = sorted(RESULTS_DIR.glob("run_*.md"), reverse=True)
    if result_files:
        st.markdown('<div class="section-header">Past Run Results</div>', unsafe_allow_html=True)
        for rf in result_files[:5]:
            with st.expander(rf.stem, expanded=False):
                st.markdown(rf.read_text(encoding="utf-8"))

# ---------------------------------------------------------------------------
# How it works
# ---------------------------------------------------------------------------
with st.expander("How it works", expanded=False):
    st.markdown(
        """
**Purpose:** Validate that our detection rules actually fire when real attacker
behaviour is executed on a Windows endpoint via the Sliver C2 framework.

**Workflow (once connected):**
1. Connect to a running Sliver C2 server via its gRPC API
2. Task an active implant to execute each of the **{scenarios}** scenarios ({steps} steps)
3. Wait for Elastic to ingest the resulting events, then query for matching alerts
4. Compare expected detections against actually-fired alerts
5. Report per-scenario results: rules fired, rules missed, unexpected alerts,
   and an overall detection coverage score

**What you see on this page:**
- **Scenarios** -- the {scenarios} attack chains and their individual steps,
  pulled directly from the test harness definitions
- **Coverage Breakdown** -- how the ruleset maps to each scenario and platform,
  derived from the coverage map ({rules} rules total, {win} Windows)
- **Attack Timeline** -- a downloadable HTML visualisation of all scenario steps
  with MITRE ATT&CK references

**Current state:** The scenarios and coverage mapping are complete. The Sliver
and Elasticsearch connections are stubs that still need to be wired up before
live test runs can be executed from this page.
        """.format(
            scenarios=len(SCENARIOS),
            steps=total_steps,
            rules=total_rules,
            win=total_win,
        )
    )
