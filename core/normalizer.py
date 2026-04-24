# core/normalizer.py
"""
ECS field normalization, token extraction, and Jaccard similarity.
Pure Python — no Streamlit, no SIEM dependencies.
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Token extraction regexes (same patterns as original utils.py)
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
    """Extract ECS fields, event categories, and meaningful quoted values from an EQL query."""
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
    """Return only the @cat: prefixed tokens from a token set."""
    return frozenset(t for t in tokens if t.startswith("@cat:"))


def jaccard(a: frozenset, b: frozenset) -> float:
    """Jaccard similarity between two token sets. Returns 0.0 if both empty."""
    if not a and not b:
        return 0.0
    union = len(a | b)
    return len(a & b) / union if union else 0.0


def normalize_elastic_mitre_tag(tag: str) -> str | None:
    """
    Convert an Elastic SIEM MITRE tag to attack.* format.
    Returns None if the tag is not a recognized MITRE tag.

    Examples:
        "Tactic: Execution"                               -> "attack.execution"
        "Technique: Command and Scripting (T1059)"        -> "attack.t1059"
        "Subtechnique: PowerShell (T1059.001)"            -> "attack.t1059.001"
    """
    m = re.match(r"^Tactic:\s*(.+)$", tag, re.I)
    if m:
        return "attack." + m.group(1).strip().lower().replace(" ", "-")
    m = re.match(r"^(?:Technique|Subtechnique):.*\(([Tt]\d+(?:\.\d+)?)\)\s*$", tag)
    if m:
        return "attack." + m.group(1).lower()
    return None


def risk_to_severity(risk: int) -> str:
    """Convert a numeric risk score (0-100) to a severity label."""
    if risk >= 99:
        return "critical"
    if risk >= 73:
        return "high"
    if risk >= 47:
        return "medium"
    return "low"


SEVERITY_TO_RISK: dict[str, int] = {
    "critical": 99,
    "high": 73,
    "medium": 47,
    "low": 21,
    "informational": 21,
}

SEV_COLORS: dict[str, str] = {
    "critical": "#f85149",
    "high": "#d29922",
    "medium": "#58a6ff",
    "low": "#3fb950",
    "?": "#8b949e",
}
