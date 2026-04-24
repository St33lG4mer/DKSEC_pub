# tests/core/test_normalizer.py
from core.normalizer import (
    extract_eql_tokens,
    get_event_categories,
    jaccard,
    normalize_elastic_mitre_tag,
    risk_to_severity,
)


def test_extract_eql_tokens_fields():
    tokens = extract_eql_tokens('process where process.name == "cmd.exe"')
    assert "process.name" in tokens


def test_extract_eql_tokens_event_category():
    tokens = extract_eql_tokens('process where process.name == "cmd.exe"')
    assert "@cat:process" in tokens


def test_extract_eql_tokens_quoted_value():
    tokens = extract_eql_tokens('process where process.name == "powershell.exe"')
    assert "@val:powershell.exe" in tokens


def test_extract_eql_tokens_stops_short_values():
    tokens = extract_eql_tokens('process where process.name == "ok"')
    # "ok" is shorter than 3 chars in re.search(r"[a-z]{3,}") — not added
    assert not any(t.startswith("@val:ok") for t in tokens)


def test_extract_eql_tokens_empty():
    assert extract_eql_tokens("") == frozenset()


def test_get_event_categories():
    tokens = frozenset(["process.name", "@cat:process", "@val:cmd.exe"])
    cats = get_event_categories(tokens)
    assert cats == frozenset(["@cat:process"])


def test_jaccard_identical():
    a = frozenset(["a", "b", "c"])
    assert jaccard(a, a) == 1.0


def test_jaccard_disjoint():
    a = frozenset(["a", "b"])
    b = frozenset(["c", "d"])
    assert jaccard(a, b) == 0.0


def test_jaccard_partial():
    a = frozenset(["a", "b", "c"])
    b = frozenset(["b", "c", "d"])
    score = jaccard(a, b)
    assert abs(score - 2 / 4) < 1e-9  # intersection=2, union=4


def test_jaccard_both_empty():
    assert jaccard(frozenset(), frozenset()) == 0.0


def test_normalize_elastic_mitre_tag_tactic():
    result = normalize_elastic_mitre_tag("Tactic: Execution")
    assert result == "attack.execution"


def test_normalize_elastic_mitre_tag_technique():
    result = normalize_elastic_mitre_tag("Technique: Command and Scripting Interpreter (T1059)")
    assert result == "attack.t1059"


def test_normalize_elastic_mitre_tag_subtechnique():
    result = normalize_elastic_mitre_tag("Subtechnique: PowerShell (T1059.001)")
    assert result == "attack.t1059.001"


def test_normalize_elastic_mitre_tag_unrecognized():
    assert normalize_elastic_mitre_tag("OS: Windows") is None


def test_risk_to_severity_boundaries():
    assert risk_to_severity(99) == "critical"
    assert risk_to_severity(73) == "high"
    assert risk_to_severity(47) == "medium"
    assert risk_to_severity(21) == "low"
    assert risk_to_severity(0) == "low"
    assert risk_to_severity(100) == "critical"
