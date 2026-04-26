# storage/rule_store.py
"""Read and write RuleAST JSON files under catalogs/<catalog>/ast/."""
from __future__ import annotations

from pathlib import Path

from core.ast_model import RuleAST


class RuleStore:
    """
    File-based store for canonical RuleAST objects.
    Layout: <base_dir>/<catalog>/ast/<rule_id>.json
    """

    def __init__(self, base_dir: Path) -> None:
        self.base_dir = Path(base_dir)

    def _ast_dir(self, catalog: str) -> Path:
        d = self.base_dir / catalog / "ast"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def save(self, rule: RuleAST) -> Path:
        """Write a RuleAST to disk. Returns the file path written."""
        path = self._ast_dir(rule.catalog) / f"{rule.id}.json"
        path.write_text(rule.to_json(), encoding="utf-8")
        return path

    def load(self, rule_id: str, catalog: str) -> RuleAST:
        """Load a single RuleAST by id and catalog. Raises FileNotFoundError if missing."""
        path = self.base_dir / catalog / "ast" / f"{rule_id}.json"
        if not path.exists():
            raise FileNotFoundError(f"Rule not found: {path}")
        return RuleAST.from_json(path.read_text(encoding="utf-8"))

    def load_all(self, catalog: str) -> list[RuleAST]:
        """Load all RuleAST files for a given catalog. Returns empty list if none exist."""
        ast_dir = self.base_dir / catalog / "ast"
        if not ast_dir.exists():
            return []
        rules = []
        for path in sorted(ast_dir.glob("*.json")):
            try:
                rules.append(RuleAST.from_json(path.read_text(encoding="utf-8")))
            except Exception:
                continue
        return rules

    def list_catalogs(self) -> list[str]:
        """Return catalog names that have an ast/ subdirectory with at least one file."""
        if not self.base_dir.exists():
            return []
        return [
            d.name for d in sorted(self.base_dir.iterdir())
            if d.is_dir() and (d / "ast").exists() and any((d / "ast").glob("*.json"))
        ]

    # --- raw rule storage (pre-parse, pre-translate) ---

    def _raw_dir(self, catalog: str) -> Path:
        d = self.base_dir / catalog / "raw"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def save_raw(self, catalog: str, raws: list[dict]) -> Path:
        """
        Persist raw rule dicts (as returned by adapter.load()) to
        <base_dir>/<catalog>/raw/rules.json.
        Overwrites any existing file for this catalog.
        """
        import json
        path = self._raw_dir(catalog) / "rules.json"
        path.write_text(json.dumps(raws, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def load_raw(self, catalog: str) -> list[dict]:
        """
        Load raw rule dicts from <base_dir>/<catalog>/raw/rules.json.
        Returns empty list if the file does not exist.
        """
        import json
        path = self.base_dir / catalog / "raw" / "rules.json"
        if not path.exists():
            return []
        return json.loads(path.read_text(encoding="utf-8"))
