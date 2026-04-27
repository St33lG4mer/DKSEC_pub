# ui/pages/comparison.py
"""Comparison page — catalog picker + overlap/unique analysis + inline triage."""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
import streamlit as st

from core import mitre_mapping as _mitre_mapping
from core.theme import apply_theme
from pipeline.compare import compare_rules
from storage.result_store import ResultStore
from storage.rule_store import RuleStore

ALL_TACTICS = _mitre_mapping.ALL_TACTICS
rules_coverage_by_tactic = _mitre_mapping.rules_coverage_by_tactic


def _fallback_count_rules_without_mitre_tactics(rules: list[dict]) -> int:
    """Compatibility fallback when older mitre_mapping modules are deployed."""
    tactic_slugs = {t.lower().replace(" ", "-") for t in ALL_TACTICS}
    technique_to_tactics = getattr(_mitre_mapping, "technique_to_tactics", None)

    unmapped = 0
    for rule in rules:
        techniques = rule.get("mitre_techniques") or []
        mapped = False

        for raw in techniques:
            if not isinstance(raw, str):
                continue

            cleaned = re.sub(r"^attack\.", "", raw.strip().lower())
            cleaned = cleaned.replace("_", "-")
            cleaned = re.sub(r"\s+", "-", cleaned)
            cleaned = re.sub(r"-+", "-", cleaned)
            if cleaned in tactic_slugs:
                mapped = True
                break

            if callable(technique_to_tactics) and technique_to_tactics(raw):
                mapped = True
                break

        if not mapped:
            unmapped += 1

    return unmapped


count_rules_without_mitre_tactics = getattr(
    _mitre_mapping,
    "count_rules_without_mitre_tactics",
    _fallback_count_rules_without_mitre_tactics,
)

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
    threshold = st.slider("Jaccard threshold", 0.05, 0.80, 0.40, 0.05)
    run_id = None
    runs = result_store.list_alert_runs()
    if runs:
        use_alerts = st.checkbox("Include alert data", value=True)
        if use_alerts:
            run_id = st.selectbox("Attack run", runs, index=len(runs) - 1)
            _sidebar_alerts = result_store.load_alerts(run_id)
            _sidebar_scenarios = len({a.get("scenario_id") for a in _sidebar_alerts if a.get("scenario_id")})
            st.caption(f"Coverage Map: {_sidebar_scenarios} scenarios, {len(_sidebar_alerts):,} alerts")

if catalog_a == catalog_b:
    st.error("Select two different catalogs.")
    st.stop()

rules_a = store.load_all(catalog_a)
rules_b = store.load_all(catalog_b)

if not rules_a or not rules_b:
    st.warning("One or both catalogs are empty. Run `dksec ingest` and `dksec translate` first.")
    st.stop()

alerts = result_store.load_alerts(run_id) if run_id else None

comparison_key = (
    catalog_a,
    catalog_b,
    float(threshold),
    run_id or "",
    len(rules_a),
    len(rules_b),
    len(alerts or []),
)

if st.session_state.get("cmp_cache_key") != comparison_key:
    with st.spinner("Analysing coverage…"):
        result = compare_rules(rules_a, rules_b, alerts=alerts, threshold=threshold)

    # Persist only when a new comparison run is computed.
    overlaps_dicts, unique_a_dicts = result.to_storage_dicts()
    result_store.save_overlaps(catalog_a, catalog_b, overlaps_dicts)
    result_store.save_unique(catalog_a, catalog_b, unique_a_dicts)
    result_store.save_unique(catalog_b, catalog_a, [r.to_dict() for r in result.unique_b])

    st.session_state["cmp_cache_key"] = comparison_key
    st.session_state["cmp_cached_result"] = result
else:
    result = st.session_state["cmp_cached_result"]

# Load existing decisions (persisted from previous sessions)
decisions: dict[str, str] = result_store.load_decisions(catalog_a, catalog_b)

# Summary metrics
c1, c2, c3, c4 = st.columns(4)
c1.metric(f"{catalog_a.title()} rules", len(rules_a))
c2.metric(f"{catalog_b.title()} rules", len(rules_b))
c3.metric("Overlaps", len(result.overlaps))
c4.metric(f"Gaps (add to {catalog_b.title()})", len(result.unique_a))

st.caption(f"Confidence: **{result.confidence}**")
if result.confidence == "full":
    st.success("✅ Full confidence — includes attack chain alert data")
else:
    st.info("🔬 Logic-only — run the Attack Chain to add empirical confirmation")

if result.confidence == "full":
    alert_confirmed = sum(1 for p in result.overlaps if p.alert_confirmed)
    logic_only = len(result.overlaps) - alert_confirmed
    ac1, ac2 = st.columns(2)
    ac1.metric("Alert-confirmed overlaps", alert_confirmed)
    ac2.metric("Logic-only overlaps", logic_only)
else:
    if not runs:
        st.page_link("pages/attack_chain.py", label="→ Run Attack Chain", icon="⚔️")

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
                    st.caption(f"📂 Source: **{catalog_a.title()}** rule")
                    st.markdown(f"**Description:** {rule.description or '_No description provided._'}")

                    if rule.conditions:
                        st.markdown(f"**{catalog_a.title()} Conditions:**")
                        cond_lines = [
                            f"- `{c.field}` {c.operator} `{', '.join(c.values)}`"
                            for c in rule.conditions
                        ]
                        st.markdown("\n".join(cond_lines))

                    if rule.translated_query:
                        query_label = f"**Translated Query** (for {catalog_b.title()}):"
                        query = rule.translated_query
                    else:
                        query_label = f"**Original {catalog_a.title()} Query:**"
                        query = rule.raw_query or "_No query available_"
                    st.markdown(query_label)
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

                st.divider()
                s1, s2, s3, s4 = st.columns(4)
                composite = getattr(pair, "jaccard_score", 0.0)
                value_s   = getattr(pair, "value_score",   0.0)
                name_s    = getattr(pair, "name_score",    0.0)
                mitre_s   = getattr(pair, "mitre_score",   0.0)
                s1.metric("🎯 Composite",   f"{round(composite * 100)}%")
                s2.metric("🔬 Value Match", f"{round(value_s   * 100)}%")
                s3.metric("📛 Name Match",  f"{round(name_s    * 100)}%")
                s4.metric("🛡 MITRE",       f"{round(mitre_s   * 100)}%")
                if composite >= 0.40:
                    st.success("Strong match")
                elif composite >= 0.25:
                    st.info("Moderate match")
                else:
                    st.warning("Weak match")

                if pair.alert_confirmed:
                    st.success("Alert-confirmed overlap: both rules fired on the same attack scenario.")

# ── TAB 3: MITRE HEATMAP ─────────────────────────────────────────────────────
with tab_heatmap:
    st.markdown(
        f"Coverage of ATT&CK tactics in **{catalog_b}** (your SIEM). "
        "Green = well covered, Red = gaps."
    )
    coverage_mode = st.radio(
        "Coverage mode",
        ["MITRE tactics", "Overall rule coverage"],
        horizontal=True,
        help="Use overall coverage when MITRE tags are sparse or missing.",
    )

    all_b_dicts = [r.to_dict() for r in rules_b]
    gap_dicts = [r.to_dict() for r in result.unique_a]

    siem_coverage = rules_coverage_by_tactic(all_b_dicts)
    gap_coverage = rules_coverage_by_tactic(gap_dicts)
    siem_unmapped = count_rules_without_mitre_tactics(all_b_dicts)
    gap_unmapped = count_rules_without_mitre_tactics(gap_dicts)

    heatmap_rows = []
    if coverage_mode == "MITRE tactics":
        for tactic in ALL_TACTICS:
            siem_count = siem_coverage.get(tactic, 0)
            gap_count = gap_coverage.get(tactic, 0)
            total = siem_count + gap_count
            # If neither side has MITRE tags for this tactic, mark as missing data.
            pct = float(100 * siem_count / total) if total > 0 else float("nan")
            heatmap_rows.append({
                "Tactic": tactic,
                f"{catalog_b.title()} rules": siem_count,
                "Gaps (uncovered)": gap_count,
                "Coverage %": pct,
            })

        unmapped_total = siem_unmapped + gap_unmapped
        heatmap_rows.append({
            "Tactic": "Unmapped (no MITRE mapping)",
            f"{catalog_b.title()} rules": siem_unmapped,
            "Gaps (uncovered)": gap_unmapped,
            "Coverage %": float(100 * siem_unmapped / unmapped_total) if unmapped_total > 0 else float("nan"),
        })
    else:
        overall_siem = len(rules_b)
        overall_gap = len(result.unique_a)
        overall_total = overall_siem + overall_gap
        mapped_siem = overall_siem - siem_unmapped
        mapped_gap = overall_gap - gap_unmapped
        mapped_total = mapped_siem + mapped_gap
        unmapped_total = siem_unmapped + gap_unmapped

        heatmap_rows.extend([
            {
                "Tactic": "Overall (all rules)",
                f"{catalog_b.title()} rules": overall_siem,
                "Gaps (uncovered)": overall_gap,
                "Coverage %": float(100 * overall_siem / overall_total) if overall_total > 0 else float("nan"),
            },
            {
                "Tactic": "Mapped to MITRE",
                f"{catalog_b.title()} rules": mapped_siem,
                "Gaps (uncovered)": mapped_gap,
                "Coverage %": float(100 * mapped_siem / mapped_total) if mapped_total > 0 else float("nan"),
            },
            {
                "Tactic": "Unmapped (no MITRE mapping)",
                f"{catalog_b.title()} rules": siem_unmapped,
                "Gaps (uncovered)": gap_unmapped,
                "Coverage %": float(100 * siem_unmapped / unmapped_total) if unmapped_total > 0 else float("nan"),
            },
        ])

    df_heatmap = pd.DataFrame(heatmap_rows)

    st.dataframe(
        df_heatmap.style.background_gradient(
            subset=["Coverage %"], cmap="RdYlGn", vmin=0, vmax=100
        ).format({
            "Coverage %": lambda v: "N/A" if pd.isna(v) else f"{int(round(v))}%"
        }),
        width="stretch",
        hide_index=True,
    )

    if coverage_mode == "MITRE tactics":
        st.caption(
            "Coverage % = (SIEM rules) / (SIEM rules + gap rules). "
            "0% means the tactic is entirely uncovered in the SIEM. "
            "N/A means there was no MITRE-tagged data for that tactic in either ruleset. "
            "The final row shows fallback coverage for rules that could not be mapped to any ATT&CK tactic."
        )
    else:
        st.caption(
            "Overall mode does not require MITRE tags. "
            "It shows total rules coverage plus the mapped/unmapped split."
        )
