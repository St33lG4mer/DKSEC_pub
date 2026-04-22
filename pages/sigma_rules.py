"""Sigma Rules — validation status with human-readable failure categories."""

from pathlib import Path

import pandas as pd
import streamlit as st

from utils import (
    categorize_failure,
    complete_sigma_stems,
    load_config,
    load_failures,
    load_sigma_rules,
)

cfg = load_config()

sigma_rules = load_sigma_rules()
failures    = load_failures()
in_ruleset  = complete_sigma_stems()  # stems present in complete_ruleset/sigma/

st.title("Sigma Rule Validation")

# ── Metrics ────────────────────────────────────────────────────────────────
sigma_stems = {Path(r["path"]).stem for r in sigma_rules}
n_failures  = sum(1 for stem in failures if stem in sigma_stems)
n_valid     = len(sigma_rules) - n_failures

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Sigma rules", len(sigma_rules))
c2.metric(
    "EQL valid",
    n_valid,
    delta=f"{round(n_valid / len(sigma_rules) * 100)}%" if sigma_rules else "—",
)
c3.metric("EQL failures", n_failures)
c4.metric("In Deploy Ruleset", len(in_ruleset))

# ── Build table rows ───────────────────────────────────────────────────────
rows = []
for r in sigma_rules:
    stem   = Path(r["path"]).stem
    reason = failures.get(stem, "")
    if reason:
        cat, affected = categorize_failure(reason)
        eql_cell = f"❌ {cat}"
    else:
        cat, affected, eql_cell = "", "", "✅ Valid"

    rows.append({
        "Name":             r["title"],
        "Severity":         r["severity"],
        "Status":           r["status"],
        "EQL":              eql_cell,
        "Failure Category": cat,
        "Affected Fields":  affected,
        "In Ruleset":       "✅" if Path(r["path"]).stem in in_ruleset else "—",
        "Techniques":       len(r["techniques"]),
    })

df = pd.DataFrame(rows)

# ── Filters ────────────────────────────────────────────────────────────────
st.markdown('<div class="section-header">Rules</div>', unsafe_allow_html=True)

col_a, col_b, col_c = st.columns(3)
sev_filter = col_a.multiselect("Severity", ["critical", "high", "medium", "low"])
eql_filter = col_b.selectbox("EQL status", ["All", "Valid only", "Failures only"])
failure_cats = sorted({r["Failure Category"] for r in rows if r["Failure Category"]})
cat_filter = col_c.selectbox("Failure category", ["All"] + failure_cats)

if sev_filter:
    df = df[df["Severity"].isin(sev_filter)]
if eql_filter == "Valid only":
    df = df[df["EQL"].str.startswith("✅")]
elif eql_filter == "Failures only":
    df = df[df["EQL"].str.startswith("❌")]
if cat_filter != "All":
    df = df[df["Failure Category"] == cat_filter]

st.dataframe(df, width="stretch", height=500)

# ── Failure breakdown charts ───────────────────────────────────────────────
if failures:
    st.markdown(
        '<div class="section-header">Failure Breakdown</div>', unsafe_allow_html=True
    )
    col_left, col_right = st.columns(2)

    with col_left:
        st.caption("By failure category")
        cat_counts: dict[str, int] = {}
        for r in rows:
            if r["Failure Category"]:
                cat_counts[r["Failure Category"]] = cat_counts.get(r["Failure Category"], 0) + 1
        df_cat = (
            pd.DataFrame(list(cat_counts.items()), columns=["Category", "Count"])
            .sort_values("Count", ascending=False)
            .set_index("Category")
        )
        st.bar_chart(df_cat, color="#f85149")

    with col_right:
        st.caption("Most affected ECS fields")
        field_counts: dict[str, int] = {}
        for r in rows:
            for field in r["Affected Fields"].split(", "):
                field = field.strip()
                if field and field != "—":
                    field_counts[field] = field_counts.get(field, 0) + 1
        if field_counts:
            top_fields = sorted(field_counts.items(), key=lambda x: -x[1])[:15]
            df_fields = (
                pd.DataFrame(top_fields, columns=["Field", "Count"])
                .set_index("Field")
            )
            st.bar_chart(df_fields, color="#d29922")
