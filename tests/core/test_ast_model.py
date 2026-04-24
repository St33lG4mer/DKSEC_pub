# tests/core/test_ast_model.py
import json
from core.ast_model import Condition, RuleAST, ValidationResult


def _sample_rule() -> RuleAST:
    return RuleAST(
        id="abc123",
        catalog="sigma",
        name="Test Rule",
        description="A test rule",
        severity="high",
        mitre_techniques=["attack.t1059.001"],
        event_categories=["process"],
        conditions=[
            Condition(
                field="process.name",
                raw_field="Image",
                operator="==",
                values=["cmd.exe"],
                raw_values=["cmd.exe"],
            )
        ],
        raw_query='process where process.name == "cmd.exe"',
        language="eql",
        translated_query=None,
        source_path="/rules/test.yml",
        metadata={"author": "test"},
    )


def test_rule_ast_roundtrip():
    rule = _sample_rule()
    data = rule.to_dict()
    restored = RuleAST.from_dict(data)
    assert restored.id == rule.id
    assert restored.catalog == rule.catalog
    assert restored.name == rule.name
    assert restored.severity == rule.severity
    assert restored.mitre_techniques == rule.mitre_techniques
    assert restored.event_categories == rule.event_categories
    assert len(restored.conditions) == 1
    assert restored.conditions[0].field == "process.name"
    assert restored.conditions[0].values == ["cmd.exe"]
    assert restored.translated_query is None
    assert restored.metadata == {"author": "test"}


def test_rule_ast_to_json_string():
    rule = _sample_rule()
    s = rule.to_json()
    data = json.loads(s)
    assert data["id"] == "abc123"
    assert data["catalog"] == "sigma"


def test_rule_ast_from_json_string():
    rule = _sample_rule()
    restored = RuleAST.from_json(rule.to_json())
    assert restored.id == rule.id


def test_validation_result_valid():
    v = ValidationResult(valid=True)
    assert v.valid is True
    assert v.error is None


def test_validation_result_invalid():
    v = ValidationResult(valid=False, error="unknown field [process.bad]")
    assert v.valid is False
    assert "unknown field" in v.error


def test_condition_fields():
    c = Condition(
        field="process.name",
        raw_field="Image",
        operator="like~",
        values=["powershell*"],
        raw_values=["*powershell*"],
    )
    assert c.field == "process.name"
    assert c.operator == "like~"
