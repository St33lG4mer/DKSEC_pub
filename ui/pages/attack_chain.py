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
st.dataframe(rule_counts, width="stretch", hide_index=True)

with st.expander("By scenario"):
    scenario_counts = (
        df.groupby("Scenario")
        .size()
        .reset_index(name="Alerts")
        .sort_values("Alerts", ascending=False)
    )
    st.dataframe(scenario_counts, width="stretch", hide_index=True)
