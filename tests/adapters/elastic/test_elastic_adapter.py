# tests/adapters/elastic/test_elastic_adapter.py
"""Tests for ElasticAdapter.load(), parse(), translate(), validate(), deploy()."""
import pytest
from unittest.mock import patch, MagicMock

from adapters.elastic.adapter import ElasticAdapter
from core.ast_model import RuleAST, ValidationResult

SAMPLE_ELASTIC_RULE = {
    "id": "uuid-abc-123",
    "rule_id": "elastic-rule-001",
    "name": "Test Elastic Rule",
    "description": "A test elastic rule",
    "type": "eql",
    "query": 'process where process.name == "cmd.exe"',
    "risk_score": 73,
    "enabled": True,
    "tags": [
        "Technique: Command and Scripting Interpreter (T1059)",
        "Tactic: Execution",
    ],
    "author": ["Elastic"],
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-02T00:00:00Z",
}


# ---------------------------------------------------------------------------
# load() tests
# ---------------------------------------------------------------------------

def test_load_returns_rules_from_single_page():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="elastic", password="pass")
    page = MagicMock(status_code=200)
    page.json.return_value = {"data": [SAMPLE_ELASTIC_RULE], "total": 1}
    with patch("requests.get", return_value=page):
        rules = adapter.load()
    assert len(rules) == 1
    assert rules[0]["name"] == "Test Elastic Rule"


def test_load_paginates_correctly():
    rule_a = {**SAMPLE_ELASTIC_RULE, "rule_id": "rule-a"}
    rule_b = {**SAMPLE_ELASTIC_RULE, "rule_id": "rule-b"}
    page1 = MagicMock(status_code=200)
    page1.json.return_value = {"data": [rule_a], "total": 2}
    page2 = MagicMock(status_code=200)
    page2.json.return_value = {"data": [rule_b], "total": 2}
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    with patch("requests.get", side_effect=[page1, page2]):
        rules = adapter.load()
    assert len(rules) == 2
    assert {r["rule_id"] for r in rules} == {"rule-a", "rule-b"}


def test_load_stops_when_batch_is_empty():
    page1 = MagicMock(status_code=200)
    page1.json.return_value = {"data": [SAMPLE_ELASTIC_RULE], "total": 100}
    page2 = MagicMock(status_code=200)
    page2.json.return_value = {"data": [], "total": 100}
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    with patch("requests.get", side_effect=[page1, page2]):
        rules = adapter.load()
    assert len(rules) == 1


def test_load_retries_on_429_then_succeeds():
    retry_resp = MagicMock(status_code=429)
    ok_resp = MagicMock(status_code=200)
    ok_resp.json.return_value = {"data": [SAMPLE_ELASTIC_RULE], "total": 1}
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    with patch("requests.get", side_effect=[retry_resp, ok_resp]):
        with patch("time.sleep"):  # don't actually sleep in tests
            rules = adapter.load()
    assert len(rules) == 1


def test_load_raises_on_403():
    resp = MagicMock(status_code=403, text="Forbidden")
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    with patch("requests.get", return_value=resp):
        with pytest.raises(RuntimeError, match="Kibana API error 403"):
            adapter.load()


def test_load_raises_after_all_retries_exhausted():
    retry_resp = MagicMock(status_code=429, text="Too Many Requests")
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    with patch("requests.get", return_value=retry_resp):
        with patch("time.sleep"):
            with pytest.raises(RuntimeError, match="Kibana API error 429"):
                adapter.load()


# ---------------------------------------------------------------------------
# parse() tests
# ---------------------------------------------------------------------------

def test_parse_returns_rule_ast():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    assert isinstance(rule, RuleAST)


def test_parse_catalog_is_elastic():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    assert rule.catalog == "elastic"


def test_parse_uses_rule_id_as_ast_id():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    assert rule.id == "elastic-rule-001"


def test_parse_falls_back_to_id_field_when_rule_id_missing():
    raw = {**SAMPLE_ELASTIC_RULE}
    del raw["rule_id"]
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(raw)
    assert rule.id == "uuid-abc-123"


def test_parse_severity_from_risk_score():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    for risk, expected in [(99, "critical"), (73, "high"), (47, "medium"), (21, "low"), (0, "low")]:
        rule = adapter.parse({**SAMPLE_ELASTIC_RULE, "risk_score": risk})
        assert rule.severity == expected, f"risk={risk} should map to {expected}"


def test_parse_normalizes_mitre_tags():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    raw = {
        **SAMPLE_ELASTIC_RULE,
        "tags": [
            "Tactic: Execution",
            "Technique: Command and Scripting Interpreter (T1059)",
            "Subtechnique: PowerShell (T1059.001)",
        ],
    }
    rule = adapter.parse(raw)
    assert "attack.execution" in rule.mitre_techniques
    assert "attack.t1059" in rule.mitre_techniques
    assert "attack.t1059.001" in rule.mitre_techniques


def test_parse_non_mitre_tags_excluded_from_techniques():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    raw = {**SAMPLE_ELASTIC_RULE, "tags": ["Custom Tag", "Elastic Endgame"]}
    rule = adapter.parse(raw)
    assert rule.mitre_techniques == []


def test_parse_raw_query_preserved():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    assert rule.raw_query == 'process where process.name == "cmd.exe"'


def test_parse_language_from_type_field():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    assert rule.language == "eql"


def test_parse_translated_query_is_none():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    assert rule.translated_query is None


def test_parse_metadata_contains_rule_id_and_enabled():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    assert rule.metadata["rule_id"] == "elastic-rule-001"
    assert rule.metadata["enabled"] is True


# ---------------------------------------------------------------------------
# translate() tests
# ---------------------------------------------------------------------------

def test_translate_copies_raw_to_translated():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    result = adapter.translate(rule)
    assert result.translated_query == rule.raw_query


def test_translate_returns_same_ast_object():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    result = adapter.translate(rule)
    assert result is rule


# ---------------------------------------------------------------------------
# validate() tests
# ---------------------------------------------------------------------------

def test_validate_returns_config_error_when_no_es_host():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    result = adapter.validate(rule)
    assert result.valid is False
    assert result.category == "config_error"


def test_validate_returns_valid_on_200():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p", es_host="http://es:9200")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    adapter.translate(rule)
    ok = MagicMock(status_code=200)
    with patch("requests.Session.post", return_value=ok):
        result = adapter.validate(rule)
    assert result.valid is True


def test_validate_returns_eql_error_on_400():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p", es_host="http://es:9200")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    adapter.translate(rule)
    err_resp = MagicMock(status_code=400)
    err_resp.json.return_value = {"error": {"reason": "parsing_exception"}}
    with patch("requests.Session.post", return_value=err_resp):
        result = adapter.validate(rule)
    assert result.valid is False
    assert result.category == "eql_error"


def test_validate_returns_connection_error_on_exception():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p", es_host="http://es:9200")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    adapter.translate(rule)
    with patch("requests.Session.post", side_effect=ConnectionError("refused")):
        result = adapter.validate(rule)
    assert result.valid is False
    assert result.category == "connection_error"


# ---------------------------------------------------------------------------
# deploy() tests
# ---------------------------------------------------------------------------

def test_deploy_returns_true_on_201():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    adapter.translate(rule)
    resp = MagicMock(status_code=201)
    with patch("requests.post", return_value=resp):
        assert adapter.deploy(rule) is True


def test_deploy_returns_true_on_200():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    adapter.translate(rule)
    resp = MagicMock(status_code=200)
    with patch("requests.post", return_value=resp):
        assert adapter.deploy(rule) is True


def test_deploy_returns_false_on_409():
    adapter = ElasticAdapter(kibana_url="http://kibana:5601", user="u", password="p")
    rule = adapter.parse(SAMPLE_ELASTIC_RULE)
    adapter.translate(rule)
    resp = MagicMock(status_code=409)
    with patch("requests.post", return_value=resp):
        assert adapter.deploy(rule) is False
