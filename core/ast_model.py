# core/ast_model.py
"""Canonical rule data model shared across all catalog adapters."""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field


@dataclass
class Condition:
    """A single normalized condition within a rule."""
    field: str          # ECS-normalized field name, e.g. "process.name"
    raw_field: str      # Original field name from the source catalog
    operator: str       # "==" | "!=" | "like~" | "in" | "wildcard" | ":"
    values: list[str]   # Normalized values
    raw_values: list[str]  # Original values

    def to_dict(self) -> dict:
        return {
            "field": self.field,
            "raw_field": self.raw_field,
            "operator": self.operator,
            "values": self.values,
            "raw_values": self.raw_values,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Condition":
        return cls(
            field=d["field"],
            raw_field=d.get("raw_field", d["field"]),
            operator=d["operator"],
            values=d["values"],
            raw_values=d.get("raw_values", d["values"]),
        )


@dataclass
class RuleAST:
    """
    Canonical representation of a detection rule, catalog-agnostic.
    All adapters normalize their source format into this structure.
    """
    id: str                        # Stable UUID (generated on first parse)
    catalog: str                   # "sigma" | "elastic" | "splunk" | ...
    name: str
    description: str
    severity: str                  # "critical" | "high" | "medium" | "low"
    mitre_techniques: list[str]    # e.g. ["attack.t1059.001"]
    event_categories: list[str]    # e.g. ["process", "network"]
    conditions: list[Condition]
    raw_query: str                 # Original query string, unchanged
    language: str                  # "eql" | "kuery" | "esql" | "sigma" | ...
    translated_query: str | None   # ECS-normalized query set by translate step
    source_path: str               # Original file path or API endpoint
    metadata: dict = field(default_factory=dict)  # Catalog-specific extras

    @classmethod
    def new_id(cls) -> str:
        return str(uuid.uuid4())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "catalog": self.catalog,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "mitre_techniques": self.mitre_techniques,
            "event_categories": self.event_categories,
            "conditions": [c.to_dict() for c in self.conditions],
            "raw_query": self.raw_query,
            "language": self.language,
            "translated_query": self.translated_query,
            "source_path": self.source_path,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RuleAST":
        return cls(
            id=d["id"],
            catalog=d["catalog"],
            name=d["name"],
            description=d.get("description", ""),
            severity=d["severity"],
            mitre_techniques=d.get("mitre_techniques", []),
            event_categories=d.get("event_categories", []),
            conditions=[Condition.from_dict(c) for c in d.get("conditions", [])],
            raw_query=d.get("raw_query", ""),
            language=d.get("language", "eql"),
            translated_query=d.get("translated_query"),
            source_path=d.get("source_path", ""),
            metadata=d.get("metadata", {}),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    @classmethod
    def from_json(cls, s: str) -> "RuleAST":
        return cls.from_dict(json.loads(s))


@dataclass
class ValidationResult:
    """Result of a syntax validation check on a translated query."""
    valid: bool
    error: str | None = None
    category: str | None = None  # e.g. "unknown_field", "type_mismatch", "syntax_error"
