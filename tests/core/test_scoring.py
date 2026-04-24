# tests/core/test_scoring.py
from core.ast_model import RuleAST, Condition
from core.scoring import classify_rule, normalize_scores, score_rule


def _make_rule(severity="high", techniques=None, translated_query='process where process.name == "x"'):
    return RuleAST(
        id="test-1",
        catalog="sigma",
        name="Test",
        description="",
        severity=severity,
        mitre_techniques=techniques or ["attack.t1059"],
        event_categories=["process"],
        conditions=[],
        raw_query=translated_query or "",
        language="eql",
        translated_query=translated_query,
        source_path="",
        metadata={},
    )


def test_score_rule_baseline():
    rule = _make_rule(severity="high", techniques=["attack.t1059"])
    # risk_score for high = 73, +5 for 1 technique, +10 for valid eql = 88
    score = score_rule(rule, has_overlap=False, alert_fires=0)
    assert score == 73 + 10 + 5  # risk + valid_eql + techniques


def test_score_rule_overlap_penalty():
    rule = _make_rule()
    no_overlap = score_rule(rule, has_overlap=False, alert_fires=0)
    with_overlap = score_rule(rule, has_overlap=True, alert_fires=0)
    assert with_overlap == no_overlap - 15


def test_score_rule_alert_bonus_capped():
    rule = _make_rule()
    score_10_fires = score_rule(rule, has_overlap=False, alert_fires=10)
    score_50_fires = score_rule(rule, has_overlap=False, alert_fires=50)
    assert score_10_fires == score_rule(rule, has_overlap=False, alert_fires=0) + 20
    assert score_50_fires == score_10_fires  # capped at +20


def test_score_rule_no_valid_eql():
    rule = _make_rule(translated_query=None)
    score = score_rule(rule, has_overlap=False, alert_fires=0)
    # No +10 for valid_eql
    assert score == 73 + 5  # risk + techniques only


def test_normalize_scores_range():
    rules = [_make_rule("critical"), _make_rule("low"), _make_rule("medium")]
    raw = [score_rule(r, False, 0) for r in rules]
    normalized = normalize_scores(raw)
    assert min(normalized) == 0.0
    assert max(normalized) == 100.0


def test_normalize_scores_single():
    # Single value — all get 50.0 to avoid divide-by-zero
    normalized = normalize_scores([42])
    assert normalized == [50.0]


def test_classify_rule_dead():
    assert classify_rule(alert_fires=0, severity="high") == "dead"


def test_classify_rule_noisy():
    assert classify_rule(alert_fires=60, severity="low") == "noisy"


def test_classify_rule_valuable():
    assert classify_rule(alert_fires=5, severity="critical") == "valuable"


def test_classify_rule_active():
    assert classify_rule(alert_fires=3, severity="medium") == "active"
