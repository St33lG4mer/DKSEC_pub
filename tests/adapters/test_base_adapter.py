# tests/adapters/test_base_adapter.py
import pytest
from core.ast_model import RuleAST, ValidationResult
from adapters.base import BaseAdapter


class ConcreteAdapter(BaseAdapter):
    name = "test"
    source_type = "folder"

    def load(self) -> list[dict]:
        return [{"title": "Rule A", "id": "a1"}]

    def parse(self, raw: dict) -> RuleAST:
        return RuleAST(
            id=raw["id"],
            catalog=self.name,
            name=raw["title"],
            description="",
            severity="medium",
            mitre_techniques=[],
            event_categories=[],
            conditions=[],
            raw_query="",
            language="eql",
            translated_query=None,
            source_path="",
        )

    def translate(self, ast: RuleAST) -> RuleAST:
        ast.translated_query = ast.raw_query
        return ast


class IncompleteAdapter(BaseAdapter):
    name = "incomplete"
    source_type = "folder"
    # Missing: load, parse, translate


def test_concrete_adapter_load():
    adapter = ConcreteAdapter()
    raw = adapter.load()
    assert len(raw) == 1
    assert raw[0]["title"] == "Rule A"


def test_concrete_adapter_parse():
    adapter = ConcreteAdapter()
    raw = {"title": "Rule A", "id": "a1"}
    rule = adapter.parse(raw)
    assert isinstance(rule, RuleAST)
    assert rule.name == "Rule A"
    assert rule.catalog == "test"


def test_concrete_adapter_translate():
    adapter = ConcreteAdapter()
    raw = {"title": "Rule A", "id": "a1"}
    rule = adapter.parse(raw)
    translated = adapter.translate(rule)
    assert translated.translated_query == rule.raw_query


def test_validate_default_returns_valid():
    adapter = ConcreteAdapter()
    raw = {"title": "Rule A", "id": "a1"}
    rule = adapter.parse(raw)
    result = adapter.validate(rule)
    assert isinstance(result, ValidationResult)
    assert result.valid is True


def test_deploy_raises_not_implemented():
    adapter = ConcreteAdapter()
    raw = {"title": "Rule A", "id": "a1"}
    rule = adapter.parse(raw)
    with pytest.raises(NotImplementedError):
        adapter.deploy(rule, client=None)


def test_incomplete_adapter_cannot_instantiate():
    with pytest.raises(TypeError):
        IncompleteAdapter()
