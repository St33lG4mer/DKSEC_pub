"""Home — 3-tier executive security overview."""

from pathlib import Path

import pandas as pd
import streamlit as st

from utils import (
    ALERTS_CACHE_FILE,
    SEV_COLORS,
    alert_donut_html,
    apply_theme,
    complete_sigma_stems,
    compute_coverage_pct,
    compute_signal_ratio,
    fetch_alerts_24h,
    get_critical_gaps,
    load_config,
    load_failures,
    load_kibana_rules,
    load_sigma_rules,
    metric_card_html,
)

apply_theme()

cfg        = load_config()
es_host    = cfg["elasticsearch"]["host"].rstrip("/")
es_user    = cfg["elasticsearch"]["user"]
es_pass    = cfg["elasticsearch"]["password"]
kibana_url = cfg["kibana"]["url"].rstrip("/")

sigma_rules  = load_sigma_rules()
failures     = load_failures()
kibana_rules = load_kibana_rules(kibana_url, es_user, es_pass)

if not kibana_rules:
    st.warning(
        "No cached Kibana rules found. Use the sidebar to refresh and cache rules from Kibana. "
        "Analysis is disabled until rules are cached."
    )
    st.stop()

# ── Page header ────────────────────────────────────────────────────────────
hdr_col, btn_col = st.columns([6, 1])
hdr_col.title("Security Overview")
if btn_col.button("🔃 Refresh", help="Clear alert cache and reload"):
    if ALERTS_CACHE_FILE.exists():
        ALERTS_CACHE_FILE.unlink()
    st.rerun()

# ── Fetch live alert data ──────────────────────────────────────────────────
with st.spinner("Fetching live alerts…"):
    alerts = fetch_alerts_24h(es_host, es_user, es_pass)

connected = bool(es_host) and not alerts.get("error")
if not connected:
    st.info("ℹ️ Elasticsearch not connected — showing rule inventory.")

# ── Pre-compute all derived values ────────────────────────────────────────
sigma_stems   = complete_sigma_stems()
sigma_in_set  = sum(1 for r in sigma_rules if Path(r["path"]).stem in sigma_stems)
total_sigma   = len(sigma_rules)
n_failures    = sum(1 for stem in failures if stem in sigma_stems)
n_valid       = total_sigma - n_failures

coverage_pct   = compute_coverage_pct(sigma_in_set, total_sigma)
signal_ratio   = compute_signal_ratio(alerts)
critical_gaps  = get_critical_gaps(sigma_rules, sigma_stems, failures)


def _sev_sub(sev_dict: dict) -> str:
    parts = []
    for sev in ("critical", "high", "medium", "low"):
        n = sev_dict.get(sev, 0)
        if n:
            color = SEV_COLORS[sev]
            parts.append(f'<span style="color:{color}">{n} {sev}</span>')
    return " · ".join(parts) if parts else "no alerts"


SEV_ORDER = ["critical", "high", "medium", "low"]


def _sev_df(sev_dict: dict) -> pd.DataFrame:
    rows = [(s, sev_dict.get(s, 0)) for s in SEV_ORDER if sev_dict.get(s, 0) > 0]
    return pd.DataFrame(rows, columns=["Severity", "Count"]).set_index("Severity")


# ═══════════════════════════════════════════════════════════════
# TIER 1 — Executive Snapshot
# ═══════════════════════════════════════════════════════════════
st.markdown('<div class="section-header">Executive Snapshot</div>', unsafe_allow_html=True)

gap_color = "#f85149" if critical_gaps else "#3fb950"

if connected:
    signal_color = "#f85149" if signal_ratio > 50 else ("#d29922" if signal_ratio > 20 else "#3fb950")
    card2 = metric_card_html("Signal Ratio", f"{signal_ratio:.1f}%", "high + critical / total alerts (24h)", signal_color)
    card4 = alert_donut_html(alerts["total"], alerts["by_severity"])
else:
    eql_pct = round(n_valid / total_sigma * 100) if total_sigma else 0
    elastic_rule_count = len([r for r in kibana_rules if "SIGMA" not in (r.get("tags") or [])])
    card2 = metric_card_html("EQL Validity", f"{eql_pct}%", f"{n_valid} of {total_sigma} rules pass validation", "#58a6ff")
    card4 = metric_card_html(
        "Detection Rules", f"{len(sigma_rules) + elastic_rule_count:,}",
        f"Sigma: {len(sigma_rules):,}  ·  Elastic: {elastic_rule_count:,}", "#e6edf3",
    )

st.markdown(
    '<div class="metric-row">'
    + metric_card_html("Coverage Score", f"{coverage_pct}%", f"{sigma_in_set} of {total_sigma} SIGMA rules deploy-ready", "#3fb950")
    + card2
    + metric_card_html("Critical Gaps", str(len(critical_gaps)), "high/critical SIGMA rules not deployed", gap_color)
    + card4
    + '</div>',
    unsafe_allow_html=True,
)

st.divider()

# ═══════════════════════════════════════════════════════════════
# TIER 2 — Actionable Intelligence
# ═══════════════════════════════════════════════════════════════
col_gaps, col_noisy = st.columns([3, 2])

with col_gaps:
    st.caption("CRITICAL GAPS")
    if not critical_gaps:
        st.success("No critical gaps — all high/critical SIGMA rules are deployed.")
    else:
        df_gaps = pd.DataFrame(critical_gaps)[["Name", "Severity", "Risk Score", "EQL Valid"]].head(10)
        st.dataframe(df_gaps, height=280, use_container_width=True)
        st.caption(f"{len(critical_gaps)} high/critical rules pending deployment")

with col_noisy:
    if connected:
        st.caption("TOP NOISY RULES (24h)")
        noisy_rows = [
            {"Rule": r["rule"][:40], "Count": r["count"], "Source": "SIGMA"}
            for r in alerts["sigma"]["top_rules"] if r["count"] >= 20
        ] + [
            {"Rule": r["rule"][:40], "Count": r["count"], "Source": "Elastic"}
            for r in alerts["elastic"]["top_rules"] if r["count"] >= 20
        ]
        if noisy_rows:
            df_noisy = (
                pd.DataFrame(noisy_rows)
                .sort_values("Count", ascending=False)
                .head(5)
                .reset_index(drop=True)
            )
            st.dataframe(df_noisy, height=280, use_container_width=True)
        else:
            st.info("No high-volume rules detected.")
    else:
        st.caption("TOP HIGH / CRITICAL SIGMA RULES")
        top_hc = sorted(
            [r for r in sigma_rules if r["severity"] in ("high", "critical")],
            key=lambda r: -r["risk_score"],
        )[:8]
        if top_hc:
            st.dataframe(
                pd.DataFrame([
                    {"Rule": r["title"][:38], "Severity": r["severity"], "Risk": r["risk_score"]}
                    for r in top_hc
                ]),
                height=280,
                use_container_width=True,
                hide_index=True,
            )

st.divider()

# ═══════════════════════════════════════════════════════════════
# TIER 3 — Detection Activity / Rule Inventory
# ═══════════════════════════════════════════════════════════════
if connected:
    st.markdown('<div class="section-header">Detection Activity — Last 24 Hours</div>', unsafe_allow_html=True)
    if alerts["timeline"]:
        df_tl = pd.DataFrame(alerts["timeline"])
        if not df_tl.empty and "count" in df_tl.columns:
            st.bar_chart(df_tl.set_index("hour").rename(columns={"count": "Alerts"}), color="#58a6ff")

    col_sig, col_ela = st.columns(2)
    with col_sig:
        st.caption("🔵 SIGMA — severity breakdown")
        df_sig = _sev_df(alerts["sigma"]["by_severity"])
        if not df_sig.empty:
            st.bar_chart(df_sig, color="#58a6ff")
        else:
            st.info("No SIGMA alerts in last 24 h")
    with col_ela:
        st.caption("🟡 Elastic — severity breakdown")
        df_ela = _sev_df(alerts["elastic"]["by_severity"])
        if not df_ela.empty:
            st.bar_chart(df_ela, color="#d29922")
        else:
            st.info("No Elastic alerts in last 24 h")
else:
    st.markdown('<div class="section-header">Rule Inventory</div>', unsafe_allow_html=True)
    elastic_inv = [r for r in kibana_rules if "SIGMA" not in (r.get("tags") or [])]
    col_sig, col_ela = st.columns(2)
    with col_sig:
        st.caption("🔵 SIGMA — rules by severity")
        st.bar_chart(
            _sev_df({sev: sum(1 for r in sigma_rules if r["severity"] == sev) for sev in SEV_ORDER}),
            color="#58a6ff",
        )
    with col_ela:
        st.caption("🟡 Elastic — rules by severity")
        st.bar_chart(
            _sev_df({sev: sum(1 for r in elastic_inv if r["severity"] == sev) for sev in SEV_ORDER}),
            color="#d29922",
        )

if connected:
    st.markdown('<div class="section-header">Top Triggered Rules</div>', unsafe_allow_html=True)
    all_top = [
        {"Rule": r["rule"], "Alerts": r["count"], "Source": "SIGMA"}
        for r in alerts["sigma"]["top_rules"]
    ] + [
        {"Rule": r["rule"], "Alerts": r["count"], "Source": "Elastic"}
        for r in alerts["elastic"]["top_rules"]
    ]
    if all_top:
        df_top = (
            pd.DataFrame(all_top)
            .sort_values("Alerts", ascending=False)
            .head(15)
            .reset_index(drop=True)
        )
        st.dataframe(df_top, use_container_width=True, height=360)
else:
    st.markdown('<div class="section-header">Top Sigma Rules by Risk Score</div>', unsafe_allow_html=True)
    top_scored = sorted(sigma_rules, key=lambda r: -r["risk_score"])[:15]
    st.dataframe(
        pd.DataFrame([
            {"Rule": r["title"], "Severity": r["severity"], "Risk Score": r["risk_score"],
             "MITRE Techniques": len(r["techniques"])}
            for r in top_scored
        ]),
        use_container_width=True,
        height=360,
        hide_index=True,
    )

st.divider()

# ═══════════════════════════════════════════════════════════════
# TIER 4 — Rule Health
# ═══════════════════════════════════════════════════════════════
st.caption("RULE HEALTH")
h1, h2, h3, h4 = st.columns(4)
h1.metric("Total SIGMA rules", total_sigma)
h2.metric("EQL valid", n_valid, delta=f"{round(n_valid / total_sigma * 100)}%" if total_sigma else "—")
h3.metric("EQL failures", n_failures)
h4.metric("Deploy-ready", sigma_in_set)
