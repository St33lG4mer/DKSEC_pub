# adapters/base.py
"""Abstract base class for all catalog adapters."""
from __future__ import annotations

from abc import ABC, abstractmethod

from core.ast_model import RuleAST, ValidationResult


class BaseAdapter(ABC):
    """
    Contract that every catalog adapter must implement.
    A catalog adapter knows how to:
      1. load()      -- fetch raw rules from a source (git/folder/API)
      2. parse()     -- convert one raw rule dict to a canonical RuleAST
      3. translate() -- normalize the rule's query/fields to ECS
      4. validate()  -- syntax-check the translated query (optional)
      5. deploy()    -- push a rule to a SIEM (optional)

    New catalog support = new folder under adapters/ with one adapter.py
    implementing this interface. No other files need to change.
    """

    name: str          # Catalog identifier, e.g. "sigma", "elastic"
    source_type: str   # "git" | "folder" | "api"

    @abstractmethod
    def load(self) -> list[dict]:
        """
        Fetch raw rules from the configured source.
        Returns a list of raw rule dicts (catalog-specific format).
        """

    @abstractmethod
    def parse(self, raw: dict) -> RuleAST:
        """
        Convert a single raw rule dict to a canonical RuleAST.
        The returned RuleAST.translated_query should be None at this stage.
        """

    @abstractmethod
    def translate(self, ast: RuleAST) -> RuleAST:
        """
        Normalize the rule's query and field names to ECS.
        Sets ast.translated_query. Returns the updated ast.
        """

    def validate(self, ast: RuleAST) -> ValidationResult:
        """
        Syntax-check the translated query against the target SIEM.
        Default implementation: always valid (no-op).
        Override in adapters that support live validation (e.g. ElasticAdapter).
        """
        return ValidationResult(valid=True)

    def deploy(self, ast: RuleAST, client) -> bool:
        """
        Push a rule to a SIEM. Returns True on success.
        Default: raises NotImplementedError.
        Override in adapters that support deployment.
        """
        raise NotImplementedError(f"{self.__class__.__name__} does not support deploy()")
