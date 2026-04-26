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

# ---------------------------------------------------------------------------
# Multi-signal composite scorer
# ---------------------------------------------------------------------------
from core.ast_model import RuleAST  # noqa: E402 — after constants to avoid circular issues

_SIG_VAL_STOP = frozenset({
    "true", "false", "null", "none", "yes", "no", "and", "or", "not",
    "high", "system", "medium", "low", "process", "file", "network",
    "windows", "linux", "any", "all",
})
_REG_HIVES = re.compile(r'^(hklm|hkcu|hku|hkcr|hkcc)', re.I)
_REG_PATHS = re.compile(r'\\(software|system|currentversion)\\', re.I)
_SAFE_CHARS = re.compile(r'^[a-z0-9.\-_]+$')

_NAME_PREFIX_STOP = frozenset({
    "proc", "process", "create", "creation", "win", "lnx", "linux", "mac",
    "osx", "aws", "gcp", "azure", "net", "network", "dns", "file", "reg",
    "registry", "event", "log", "cmd", "ps", "powershell", "script",
    "sysmon", "pipe", "image",
})
_NAME_STOP = frozenset({
    "the", "and", "via", "for", "use", "not", "new", "add", "set",
    "get", "run", "exe", "dll", "sys", "bin", "tmp", "var", "etc",
})
_NAME_SPLIT_RE = re.compile(r'[_\-.\s]+')


def _extract_values_from_list(values: list[str], already_lower: bool = False) -> set[str]:
    result: set[str] = set()
    for raw in values:
        v = raw if already_lower else raw.lower()
        if v.endswith(".exe"):
            # Keep only the filename, strip path separators
            filename = v.replace("/", "\\").rsplit("\\", 1)[-1]
            result.add(filename)
        elif _REG_HIVES.match(v) or _REG_PATHS.search(v):
            result.add(v)
        else:
            if (
                len(v) >= 4
                and _SAFE_CHARS.match(v)
                and "*" not in v
                and "?" not in v
                and v not in _SIG_VAL_STOP
            ):
                result.add(v)
    return result


def extract_significant_values(rule: RuleAST) -> frozenset[str]:
    """Extract semantically significant values from a rule's conditions."""
    result: set[str] = set()
    for cond in rule.conditions:
        result.update(_extract_values_from_list(cond.values, already_lower=True))
        result.update(_extract_values_from_list(cond.raw_values, already_lower=False))
    return frozenset(result)


def name_tokens(rule: RuleAST) -> frozenset[str]:
    """Tokenize a rule name into meaningful words, stripping catalog-specific prefixes."""
    parts = rule.name.split("_")
    # Drop leading tokens that are catalog-specific prefixes
    while parts and parts[0].lower() in _NAME_PREFIX_STOP:
        parts.pop(0)
    remaining = "_".join(parts)
    tokens = _NAME_SPLIT_RE.split(remaining)
    result: set[str] = set()
    for tok in tokens:
        t = tok.lower()
        if len(t) < 3:
            continue
        if t.isdigit():
            continue
        if t in _NAME_STOP:
            continue
        result.add(t)
    return frozenset(result)


def composite_score(rule_a: RuleAST, rule_b: RuleAST) -> tuple[float, dict[str, float]]:
    """
    Compute a weighted composite similarity score between two rules.

    Weights: value_score=0.50, name_score=0.30, mitre_score=0.20
    """
    value_score = jaccard(extract_significant_values(rule_a), extract_significant_values(rule_b))
    name_score = jaccard(name_tokens(rule_a), name_tokens(rule_b))

    mt_a = frozenset(rule_a.mitre_techniques)
    mt_b = frozenset(rule_b.mitre_techniques)
    mitre_score = jaccard(mt_a, mt_b)  # jaccard returns 0.0 when both empty

    composite = 0.50 * value_score + 0.30 * name_score + 0.20 * mitre_score
    return composite, {"value_score": value_score, "name_score": name_score, "mitre_score": mitre_score}
