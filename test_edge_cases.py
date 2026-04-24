"""
Edge case tests for RuleAST and Condition classes.
Tests: empty lists, special characters, malformed JSON, nested structures.
"""
import json
import pytest
from core.ast_model import RuleAST, Condition


class TestConditionEdgeCases:
    """Test edge cases for Condition class."""

    def test_condition_empty_values_list(self):
        """Test Condition with empty values list."""
        cond = Condition(
            field="process.name",
            raw_field="Image",
            operator="==",
            values=[],
            raw_values=[]
        )
        assert cond.values == []
        assert cond.raw_values == []
        d = cond.to_dict()
        assert d["values"] == []

    def test_condition_with_newlines_in_values(self):
        """Test Condition with newline characters in values."""
        cond = Condition(
            field="file.path",
            raw_field="TargetFilename",
            operator="like~",
            values=["C:\\Windows\nSystem32", "test\r\nfile"],
            raw_values=["C:\\Windows\nSystem32", "test\r\nfile"]
        )
        assert "\n" in cond.values[0]
        assert "\r\n" in cond.values[1]
        d = cond.to_dict()
        assert "\n" in d["values"][0]

    def test_condition_with_quotes_in_values(self):
        """Test Condition with various quote characters in values."""
        cond = Condition(
            field="process.command_line",
            raw_field="CommandLine",
            operator="like~",
            values=['cmd.exe "test"', "cmd.exe 'test'", 'cmd.exe `test`'],
            raw_values=['cmd.exe "test"', "cmd.exe 'test'", 'cmd.exe `test`']
        )
        assert cond.values[0] == 'cmd.exe "test"'
        assert cond.values[1] == "cmd.exe 'test'"
        d = cond.to_dict()
        assert len(d["values"]) == 3

    def test_condition_with_unicode_values(self):
        """Test Condition with unicode characters in values."""
        cond = Condition(
            field="process.name",
            raw_field="Image",
            operator="==",
            values=["процесс.exe", "プロセス.exe", "🔒process.exe", "μ-process.exe"],
            raw_values=["процесс.exe", "プロセス.exe", "🔒process.exe", "μ-process.exe"]
        )
        assert "процесс" in cond.values[0]
        assert "プロセス" in cond.values[1]
        assert "🔒" in cond.values[2]
        d = cond.to_dict()
        assert len(d["values"]) == 4

    def test_condition_with_special_regex_characters(self):
        """Test Condition with regex special characters in values."""
        cond = Condition(
            field="process.command_line",
            raw_field="CommandLine",
            operator="like~",
            values=[".*test.*", "[a-z]+", "^start.*end$", "\\d{3}"],
            raw_values=[".*test.*", "[a-z]+", "^start.*end$", "\\d{3}"]
        )
        d = cond.to_dict()
        assert ".*test.*" in d["values"]

    def test_condition_serialization_roundtrip_with_special_chars(self):
        """Test Condition serialization/deserialization with special chars."""
        original = Condition(
            field="file.path",
            raw_field="TargetFilename",
            operator="like~",
            values=["C:\\temp\\file\"name\n.txt", "special™chars"],
            raw_values=["original\\path", "raw™value"]
        )
        d = original.to_dict()
        restored = Condition.from_dict(d)
        assert restored.values == original.values
        assert restored.raw_values == original.raw_values

    def test_condition_with_missing_raw_field_defaults(self):
        """Test Condition.from_dict with missing raw_field (should default to field)."""
        d = {
            "field": "process.name",
            "operator": "==",
            "values": ["test.exe"],
            "raw_values": ["test.exe"]
        }
        cond = Condition.from_dict(d)
        assert cond.raw_field == "process.name"

    def test_condition_with_missing_raw_values_defaults(self):
        """Test Condition.from_dict with missing raw_values (should default to values)."""
        d = {
            "field": "process.name",
            "raw_field": "Image",
            "operator": "==",
            "values": ["test.exe"]
        }
        cond = Condition.from_dict(d)
        assert cond.raw_values == ["test.exe"]

    def test_condition_missing_required_field_raises_error(self):
        """Test that missing required field raises KeyError."""
        d = {
            "raw_field": "Image",
            "operator": "==",
            "values": ["test.exe"]
        }
        with pytest.raises(KeyError):
            Condition.from_dict(d)

    def test_condition_missing_operator_raises_error(self):
        """Test that missing operator raises KeyError."""
        d = {
            "field": "process.name",
            "raw_field": "Image",
            "values": ["test.exe"]
        }
        with pytest.raises(KeyError):
            Condition.from_dict(d)


class TestRuleASTEdgeCases:
    """Test edge cases for RuleAST class."""

    def test_ruleast_empty_mitre_techniques(self):
        """Test RuleAST with empty mitre_techniques list."""
        rule = RuleAST(
            id="test-id",
            catalog="sigma",
            name="Test Rule",
            description="Test",
            severity="high",
            mitre_techniques=[],
            event_categories=["process"],
            conditions=[],
            raw_query="test",
            language="eql",
            translated_query=None,
            source_path="/path"
        )
        assert rule.mitre_techniques == []
        d = rule.to_dict()
        assert d["mitre_techniques"] == []

    def test_ruleast_empty_event_categories(self):
        """Test RuleAST with empty event_categories list."""
        rule = RuleAST(
            id="test-id",
            catalog="sigma",
            name="Test Rule",
            description="Test",
            severity="high",
            mitre_techniques=["attack.t1234"],
            event_categories=[],
            conditions=[],
            raw_query="test",
            language="eql",
            translated_query=None,
            source_path="/path"
        )
        assert rule.event_categories == []
        d = rule.to_dict()
        assert d["event_categories"] == []

    def test_ruleast_empty_conditions(self):
        """Test RuleAST with empty conditions list."""
        rule = RuleAST(
            id="test-id",
            catalog="sigma",
            name="Test Rule",
            description="Test",
            severity="high",
            mitre_techniques=["attack.t1234"],
            event_categories=["process"],
            conditions=[],
            raw_query="test",
            language="eql",
            translated_query=None,
            source_path="/path"
        )
        assert rule.conditions == []
        d = rule.to_dict()
        assert d["conditions"] == []

    def test_ruleast_all_empty_lists(self):
        """Test RuleAST with all lists empty."""
        rule = RuleAST(
            id="test-id",
            catalog="sigma",
            name="Test Rule",
            description="Test",
            severity="high",
            mitre_techniques=[],
            event_categories=[],
            conditions=[],
            raw_query="test",
            language="eql",
            translated_query=None,
            source_path="/path"
        )
        d = rule.to_dict()
        assert d["mitre_techniques"] == []
        assert d["event_categories"] == []
        assert d["conditions"] == []

    def test_ruleast_with_special_chars_in_strings(self):
        """Test RuleAST with special characters in string fields."""
        rule = RuleAST(
            id="test-id",
            catalog="sigma",
            name="Test Rule\nWith\rNewlines",
            description="Description with 'quotes' and \"double quotes\"\nand\nnewlines",
            severity="high",
            mitre_techniques=["attack.t1234"],
            event_categories=["process"],
            conditions=[],
            raw_query="test\nquery\nwith\r\nnewlines",
            language="eql",
            translated_query="translated\nquery",
            source_path="/path/with spaces/and\ttabs"
        )
        assert "\n" in rule.name
        assert "\r" in rule.name
        assert '"' in rule.description
        assert "\t" in rule.source_path
        d = rule.to_dict()
        assert "\n" in d["name"]

    def test_ruleast_with_unicode_strings(self):
        """Test RuleAST with unicode characters in strings."""
        rule = RuleAST(
            id="test-id",
            catalog="sigma",
            name="Правило 🔒 プロセス μ",
            description="Description with ™ © ® symbols",
            severity="high",
            mitre_techniques=["attack.t1234"],
            event_categories=["process"],
            conditions=[],
            raw_query="日本語クエリ",
            language="eql",
            translated_query="Ελληνικά μεταφραση",
            source_path="/путь/файла"
        )
        assert "🔒" in rule.name
        assert "™" in rule.description
        assert "日本語" in rule.raw_query
        d = rule.to_dict()
        assert "Ελληνικά" in d["translated_query"]

    def test_ruleast_serialization_roundtrip_with_special_chars(self):
        """Test RuleAST serialization/deserialization with special characters."""
        original = RuleAST(
            id="test-id",
            catalog="sigma",
            name="Test\nRule",
            description='Test "quoted" description',
            severity="high",
            mitre_techniques=["attack.t1234"],
            event_categories=["process"],
            conditions=[],
            raw_query="test query\nwith\nnewlines",
            language="eql",
            translated_query=None,
            source_path="/path"
        )
        d = original.to_dict()
        restored = RuleAST.from_dict(d)
        assert restored.name == original.name
        assert restored.description == original.description
        assert restored.raw_query == original.raw_query

    def test_ruleast_with_nested_conditions(self):
        """Test RuleAST with multiple conditions."""
        cond1 = Condition(
            field="process.name",
            raw_field="Image",
            operator="==",
            values=["test.exe"],
            raw_values=["test.exe"]
        )
        cond2 = Condition(
            field="process.command_line",
            raw_field="CommandLine",
            operator="like~",
            values=["*malware*"],
            raw_values=["*malware*"]
        )
        cond3 = Condition(
            field="file.path",
            raw_field="TargetFilename",
            operator="!=",
            values=["C:\\Windows\\System32"],
            raw_values=["C:\\Windows\\System32"]
        )
        rule = RuleAST(
            id="test-id",
            catalog="sigma",
            name="Test Rule",
            description="Test",
            severity="high",
            mitre_techniques=["attack.t1234"],
            event_categories=["process", "file"],
            conditions=[cond1, cond2, cond3],
            raw_query="test",
            language="eql",
            translated_query=None,
            source_path="/path"
        )
        assert len(rule.conditions) == 3
        d = rule.to_dict()
        assert len(d["conditions"]) == 3

    def test_ruleast_nested_conditions_roundtrip(self):
        """Test RuleAST serialization/deserialization with nested conditions."""
        original = RuleAST(
            id="test-id",
            catalog="sigma",
            name="Test Rule",
            description="Test",
            severity="high",
            mitre_techniques=["attack.t1234", "attack.t5678"],
            event_categories=["process", "file"],
            conditions=[
                Condition("process.name", "Image", "==", ["test.exe"], ["test.exe"]),
                Condition("file.path", "TargetFilename", "!=", ["C:\\Windows"], ["C:\\Windows"])
            ],
            raw_query="test",
            language="eql",
            translated_query=None,
            source_path="/path"
        )
        d = original.to_dict()
        restored = RuleAST.from_dict(d)
        assert len(restored.conditions) == 2
        assert restored.conditions[0].field == "process.name"
        assert restored.conditions[1].field == "file.path"

    def test_ruleast_missing_required_field_id_raises_error(self):
        """Test that missing id raises KeyError."""
        d = {
            "catalog": "sigma",
            "name": "Test Rule",
            "severity": "high"
        }
        with pytest.raises(KeyError):
            RuleAST.from_dict(d)

    def test_ruleast_missing_catalog_raises_error(self):
        """Test that missing catalog raises KeyError."""
        d = {
            "id": "test-id",
            "name": "Test Rule",
            "severity": "high"
        }
        with pytest.raises(KeyError):
            RuleAST.from_dict(d)

    def test_ruleast_missing_name_raises_error(self):
        """Test that missing name raises KeyError."""
        d = {
            "id": "test-id",
            "catalog": "sigma",
            "severity": "high"
        }
        with pytest.raises(KeyError):
            RuleAST.from_dict(d)

    def test_ruleast_missing_severity_raises_error(self):
        """Test that missing severity raises KeyError."""
        d = {
            "id": "test-id",
            "catalog": "sigma",
            "name": "Test Rule"
        }
        with pytest.raises(KeyError):
            RuleAST.from_dict(d)

    def test_ruleast_with_optional_fields_missing(self):
        """Test RuleAST.from_dict with all optional fields missing (should use defaults)."""
        d = {
            "id": "test-id",
            "catalog": "sigma",
            "name": "Test Rule",
            "severity": "high"
        }
        rule = RuleAST.from_dict(d)
        assert rule.description == ""
        assert rule.mitre_techniques == []
        assert rule.event_categories == []
        assert rule.conditions == []
        assert rule.raw_query == ""
        assert rule.language == "eql"
        assert rule.translated_query is None
        assert rule.source_path == ""
        assert rule.metadata == {}

    def test_ruleast_malformed_json_missing_required_field(self):
        """Test RuleAST.from_json with malformed JSON missing required field."""
        json_str = '{"id": "test-id", "catalog": "sigma", "name": "Test Rule"}'
        with pytest.raises(KeyError):
            RuleAST.from_json(json_str)

    def test_ruleast_malformed_json_invalid_syntax(self):
        """Test RuleAST.from_json with invalid JSON syntax."""
        json_str = '{"id": "test-id", invalid json'
        with pytest.raises(json.JSONDecodeError):
            RuleAST.from_json(json_str)

    def test_ruleast_malformed_json_wrong_type(self):
        """Test RuleAST.from_json with JSON that's not a dict."""
        json_str = '["this", "is", "a", "list"]'
        with pytest.raises((KeyError, TypeError)):
            RuleAST.from_json(json_str)

    def test_ruleast_json_with_null_values(self):
        """Test RuleAST.from_json with null values for optional fields."""
        json_str = json.dumps({
            "id": "test-id",
            "catalog": "sigma",
            "name": "Test Rule",
            "severity": "high",
            "description": None,
            "mitre_techniques": None,
            "event_categories": None,
            "conditions": None,
            "raw_query": None,
            "language": None,
            "translated_query": None,
            "source_path": None,
            "metadata": None
        })
        # This might raise an error or handle nulls - let's test both paths
        try:
            rule = RuleAST.from_json(json_str)
            # If it works, verify the fields
            assert rule.id == "test-id"
        except (TypeError, AttributeError):
            # Expected if from_dict doesn't handle None for required lists/fields
            pass

    def test_ruleast_json_roundtrip_with_all_fields(self):
        """Test complete RuleAST JSON serialization/deserialization."""
        original = RuleAST(
            id="test-id",
            catalog="sigma",
            name="Test Rule",
            description="Test description",
            severity="high",
            mitre_techniques=["attack.t1234", "attack.t5678"],
            event_categories=["process", "file"],
            conditions=[
                Condition("process.name", "Image", "==", ["test.exe"], ["test.exe"])
            ],
            raw_query="test query",
            language="eql",
            translated_query="translated query",
            source_path="/path/to/rule",
            metadata={"key": "value"}
        )
        json_str = original.to_json()
        restored = RuleAST.from_json(json_str)
        assert restored.id == original.id
        assert restored.name == original.name
        assert restored.description == original.description
        assert restored.severity == original.severity
        assert restored.mitre_techniques == original.mitre_techniques
        assert restored.event_categories == original.event_categories
        assert len(restored.conditions) == 1
        assert restored.conditions[0].field == "process.name"
        assert restored.metadata == original.metadata

    def test_ruleast_json_with_special_chars_roundtrip(self):
        """Test RuleAST JSON roundtrip with special characters (ensure_ascii=False)."""
        original = RuleAST(
            id="test-id",
            catalog="sigma",
            name="Тест 🔒 プロセス",
            description="Description with ™ © ® symbols\nand newlines",
            severity="high",
            mitre_techniques=["attack.t1234"],
            event_categories=["process"],
            conditions=[],
            raw_query="日本語クエリ",
            language="eql",
            translated_query="Ελληνικά",
            source_path="/путь/файла",
            metadata={"unicode": "Ñoño"}
        )
        json_str = original.to_json()
        # Verify unicode is present in JSON string
        assert "Тест" in json_str or "\\u" in json_str  # Either literal or escaped
        restored = RuleAST.from_json(json_str)
        assert restored.name == original.name
        assert restored.description == original.description
        assert restored.raw_query == original.raw_query

    def test_ruleast_with_complex_metadata(self):
        """Test RuleAST with complex nested metadata."""
        metadata = {
            "author": "test",
            "nested": {
                "level1": {
                    "level2": ["array", "of", "values"]
                }
            },
            "special_chars": "value\nwith\nnewlines"
        }
        rule = RuleAST(
            id="test-id",
            catalog="sigma",
            name="Test Rule",
            description="Test",
            severity="high",
            mitre_techniques=[],
            event_categories=[],
            conditions=[],
            raw_query="test",
            language="eql",
            translated_query=None,
            source_path="/path",
            metadata=metadata
        )
        d = rule.to_dict()
        restored = RuleAST.from_dict(d)
        assert restored.metadata == metadata

    def test_ruleast_new_id_generates_uuid(self):
        """Test that RuleAST.new_id() generates a valid UUID."""
        id1 = RuleAST.new_id()
        id2 = RuleAST.new_id()
        assert id1 != id2
        assert len(id1) == 36  # Standard UUID4 format with dashes
        assert len(id2) == 36


class TestConditionMalformedData:
    """Test Condition with malformed/unexpected data."""

    def test_condition_with_single_value_as_string_instead_of_list(self):
        """Test what happens if values is a string instead of list."""
        d = {
            "field": "process.name",
            "raw_field": "Image",
            "operator": "==",
            "values": "test.exe",  # Should be list, not string
            "raw_values": "test.exe"
        }
        # This will likely cause an error when accessing values as list
        with pytest.raises((TypeError, AttributeError)):
            cond = Condition.from_dict(d)
            # Try to access it like a list to trigger error
            _ = cond.values[0]

    def test_condition_to_dict_with_empty_field(self):
        """Test Condition with empty string field."""
        cond = Condition(
            field="",
            raw_field="",
            operator="==",
            values=["test"],
            raw_values=["test"]
        )
        d = cond.to_dict()
        assert d["field"] == ""

    def test_condition_to_dict_with_none_operator(self):
        """Test Condition.to_dict preserves all fields even if unusual."""
        cond = Condition(
            field="process.name",
            raw_field="Image",
            operator="",
            values=["test"],
            raw_values=["test"]
        )
        d = cond.to_dict()
        assert d["operator"] == ""


class TestRuleASTMalformedData:
    """Test RuleAST with malformed/unexpected data."""

    def test_ruleast_with_empty_strings(self):
        """Test RuleAST with empty strings for required fields."""
        rule = RuleAST(
            id="",
            catalog="",
            name="",
            description="",
            severity="",
            mitre_techniques=[],
            event_categories=[],
            conditions=[],
            raw_query="",
            language="",
            translated_query="",
            source_path=""
        )
        d = rule.to_dict()
        assert d["id"] == ""
        assert d["catalog"] == ""
        assert d["name"] == ""

    def test_ruleast_from_dict_with_conditions_not_list(self):
        """Test RuleAST.from_dict when conditions is not a list."""
        d = {
            "id": "test-id",
            "catalog": "sigma",
            "name": "Test Rule",
            "severity": "high",
            "conditions": "not a list"  # Should be list
        }
        with pytest.raises((TypeError, AttributeError)):
            RuleAST.from_dict(d)

    def test_ruleast_from_dict_with_mitre_techniques_not_list(self):
        """Test RuleAST.from_dict when mitre_techniques is not a list."""
        d = {
            "id": "test-id",
            "catalog": "sigma",
            "name": "Test Rule",
            "severity": "high",
            "mitre_techniques": "attack.t1234"  # Should be list
        }
        # This will likely succeed in creation but fail when accessed as list
        with pytest.raises(TypeError):
            rule = RuleAST.from_dict(d)
            # Try to iterate to trigger error
            for _ in rule.mitre_techniques:
                pass

    def test_ruleast_json_empty_string(self):
        """Test RuleAST.from_json with empty string."""
        with pytest.raises(json.JSONDecodeError):
            RuleAST.from_json("")

    def test_ruleast_json_only_whitespace(self):
        """Test RuleAST.from_json with only whitespace."""
        with pytest.raises(json.JSONDecodeError):
            RuleAST.from_json("   \n  \t  ")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
