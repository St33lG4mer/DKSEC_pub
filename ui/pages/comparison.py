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
    f"Gaps — {catalog_a.title()} rules to add ({len(result.unique_a)})",
    f"Overlaps ({len(result.overlaps)})",
    "MITRE Heatmap",
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
        sev_filter = st.multiselect(
            "Filter by severity", ["critical", "high", "medium", "low"],
            default=["critical", "high"],
            key="gap_sev_filter",
        )

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

        sorted_overlaps = sorted(result.overlaps, key=lambda p: p.jaccard_score, reverse=True)

        for pair in sorted_overlaps:
            alert_tag = " 🚨" if pair.alert_confirmed else ""
            with st.expander(
                f"**{pair.rule_a.name}** vs **{pair.rule_b.name}** "
                f"— Jaccard {pair.jaccard_score:.3f}{alert_tag}"
            ):
                col_a, col_b = st.columns(2)

                with col_a:
                    st.markdown(f"**{catalog_a.title()}: {pair.rule_a.name}**")
                    st.caption(
                        f"Severity: {pair.rule_a.severity} | "
                        f"MITRE: {', '.join(pair.rule_a.mitre_techniques[:3])}"
                    )
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
                    st.caption(
                        f"Severity: {pair.rule_b.severity} | "
                        f"MITRE: {', '.join(pair.rule_b.mitre_techniques[:3])}"
                    )
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
        "Green = well covered, Red = gaps."
    )

    all_b_dicts = [r.to_dict() for r in rules_b]
    gap_dicts = [r.to_dict() for r in result.unique_a]

    siem_coverage = rules_coverage_by_tactic(all_b_dicts)
    gap_coverage = rules_coverage_by_tactic(gap_dicts)

    heatmap_rows = []
    for tactic in ALL_TACTICS:
        siem_count = siem_coverage.get(tactic, 0)
        gap_count = gap_coverage.get(tactic, 0)
        total = siem_count + gap_count
        pct = int(100 * siem_count / total) if total > 0 else 0
        heatmap_rows.append({
            "Tactic": tactic,
            f"{catalog_b.title()} rules": siem_count,
            "Gaps (uncovered)": gap_count,
            "Coverage %": pct,
        })

    df_heatmap = pd.DataFrame(heatmap_rows)

    st.dataframe(
        df_heatmap.style.background_gradient(
            subset=["Coverage %"], cmap="RdYlGn", vmin=0, vmax=100
        ).format({"Coverage %": "{}%"}),
        width="stretch",
        hide_index=True,
    )

    st.caption(
        "Coverage % = (SIEM rules) / (SIEM rules + gap rules). "
        "0% means the tactic is entirely uncovered in the SIEM."
    )
