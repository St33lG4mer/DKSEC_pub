# core/theme.py
"""Streamlit GitHub Dark theme — CSS constants and helpers."""
from __future__ import annotations

import math

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
.metric-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    margin-bottom: 0;
}
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
.section-header {
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: #8b949e;
    padding-bottom: 6px;
    border-bottom: 1px solid #21262d;
    margin: 24px 0 14px;
}
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
[data-testid="stDataFrame"] { border: 1px solid #30363d; border-radius: 8px; }
[data-testid="stSidebarNav"] a { color: #8b949e !important; font-size: 0.85rem; }
[data-testid="stSidebarNav"] a:hover,
[data-testid="stSidebarNav"] a[aria-selected="true"] {
    color: #e6edf3 !important;
    background: #21262d !important;
}
.status-badge { display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:20px;font-size:0.75rem;font-weight:600; }
.status-disconnected { background:#2d1a1a;color:#f85149;border:1px solid #5a1a1a; }
.status-connected    { background:#0d2a1a;color:#3fb950;border:1px solid #1a5a30; }
.metric-card-muted { background:#0d1117;border:1px solid #21262d;border-radius:10px;padding:20px 22px 16px;text-align:center;opacity:0.55; }
.metric-card-muted .mc-label { font-size:0.70rem;color:#484f58;text-transform:uppercase;letter-spacing:0.10em;margin-bottom:8px; }
.metric-card-muted .mc-value { font-size:2.4rem;font-weight:700;color:#484f58;line-height:1.1; }
.metric-card-muted .mc-sub   { font-size:0.78rem;color:#30363d;margin-top:6px; }
</style>
"""


def apply_theme() -> None:
    """Inject the GitHub Dark CSS into the current Streamlit page."""
    import streamlit as st
    st.markdown(THEME_CSS, unsafe_allow_html=True)


def metric_card_html(label: str, value: str, sub: str = "", color: str = "#e6edf3") -> str:
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
    """SVG donut chart inside a metric-card div."""
    from core.normalizer import SEV_COLORS
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
    bg = f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#21262d" stroke-width="{sw}" />'
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
