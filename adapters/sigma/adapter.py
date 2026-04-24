# adapters/sigma/adapter.py
"""SigmaAdapter — loads Sigma YAML rules and translates them to EQL."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from adapters.base import BaseAdapter
from core.ast_model import RuleAST, ValidationResult
from core.sources.folder_source import FolderSource

# Sigma level → canonical severity label
_LEVEL_TO_SEVERITY: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "low",
}

_TECHNIQUE_RE = re.compile(r"^attack\.[tT]\d+", re.I)


class SigmaAdapter(BaseAdapter):
    """
    Adapter for Sigma detection rules stored in a local folder.

    load()      — walks folder_path for *.yml files, filters by status
    parse()     — converts Sigma YAML dict to RuleAST (language="sigma")
    translate() — converts Sigma YAML to EQL via pySigma EqlBackend
    """

    name = "sigma"
    source_type = "folder"

    def __init__(
        self,
        folder_path: str | Path,
        status_filter: set[str] | None = None,
    ) -> None:
        self.folder_path = Path(folder_path)
        self.status_filter = status_filter if status_filter is not None else {"stable", "test"}

    def load(self) -> list[dict]:
        """
        Walk folder_path for *.yml files.
        Filter by status_filter. Skip malformed YAML silently.
        Returns list of {"path": str, "text": str, "meta": dict}.
        Raises FileNotFoundError if folder_path does not exist.
        """
        source = FolderSource(self.folder_path, glob_pattern="**/*.yml")
        result: list[dict] = []
        for path, text in source.iter_contents():
            try:
                meta = yaml.safe_load(text) or {}
            except Exception:
                continue
            status = meta.get("status", "")
            if status not in self.status_filter:
                continue
            result.append({"path": str(path), "text": text, "meta": meta})
        return result

    def parse(self, raw: dict) -> RuleAST:
        """
        Convert a raw Sigma rule dict (as returned by load()) to a canonical RuleAST.
        translated_query is always None at this stage.
        """
        meta = raw.get("meta", {})
        sigma_id = str(meta["id"]) if meta.get("id") else RuleAST.new_id()
        title = meta.get("title") or Path(raw.get("path", "unknown")).stem
        description = meta.get("description", "")
        level = (meta.get("level") or "medium").lower()
        severity = _LEVEL_TO_SEVERITY.get(level, "medium")

        raw_tags: list[str] = [t for t in (meta.get("tags") or []) if isinstance(t, str)]
        mitre_techniques = [t for t in raw_tags if _TECHNIQUE_RE.match(t)]

        logsource: dict = meta.get("logsource") or {}
        event_categories: list[str] = []
        if logsource.get("category"):
            event_categories.append(logsource["category"])

        return RuleAST(
            id=sigma_id,
            catalog="sigma",
            name=title,
            description=description,
            severity=severity,
            mitre_techniques=mitre_techniques,
            event_categories=event_categories,
            conditions=[],
            raw_query=raw.get("text", ""),
            language="sigma",
            translated_query=None,
            source_path=raw.get("path", ""),
            metadata={
                "author": meta.get("author", ""),
                "status": meta.get("status", ""),
                "tags": raw_tags,
                "logsource": logsource,
            },
        )

    def translate(self, ast: RuleAST) -> RuleAST:
        """
        Convert the Sigma YAML in ast.raw_query to EQL via pySigma.
        Sets ast.translated_query to the EQL string, or None if translation fails.
        """
        from adapters.sigma.translator import sigma_to_eql

        ast.translated_query = sigma_to_eql(ast.raw_query)
        return ast

    def validate(self, ast: RuleAST) -> ValidationResult:
        """Default: always valid (no live ES required for Sigma rules)."""
        return ValidationResult(valid=True)
