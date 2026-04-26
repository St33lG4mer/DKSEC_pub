"""
Step 2 of the DKSec pipeline: parse raw rules into canonical RuleAST and
translate them to ECS-normalized form via the catalog adapter.

Usage:
    from adapters.sigma.adapter import SigmaAdapter
    from pipeline.translate import translate_catalog
    from storage.rule_store import RuleStore
    from pathlib import Path

    adapter = SigmaAdapter(folder_path="catalogs/sigma/raw")
    store = RuleStore(Path("catalogs"))
    result = translate_catalog(adapter, store)
    print(f"Translated {result.translated_count} rules ({result.failed_count} failed)")
"""
from __future__ import annotations

from dataclasses import dataclass, field

from adapters.base import BaseAdapter
from storage.rule_store import RuleStore


@dataclass
class TranslateResult:
    """Summary of a single catalog translate run."""

    catalog: str
    translated_count: int
    failed_count: int
    errors: list[str] = field(default_factory=list)


def translate_catalog(adapter: BaseAdapter, store: RuleStore) -> TranslateResult:
    """
    Parse and translate raw rules for a catalog, persisting the results.

    Reads raw rule dicts from store.load_raw(), calls adapter.parse() then
    adapter.translate() on each, and saves the resulting RuleAST via store.save().
    Per-rule failures are recorded in errors and counted in failed_count —
    translate_catalog never raises.

    Args:
        adapter:  A BaseAdapter implementation
        store:    RuleStore pointing at the catalogs/ directory

    Returns:
        TranslateResult with translated_count, failed_count, and errors
    """
    raws = store.load_raw(adapter.name)
    translated_count = 0
    failed_count = 0
    errors: list[str] = []

    for raw in raws:
        try:
            ast = adapter.parse(raw)
            ast = adapter.translate(ast)
            store.save(ast)
            translated_count += 1
        except Exception as exc:  # noqa: BLE001
            failed_count += 1
            errors.append(str(exc))

    return TranslateResult(
        catalog=adapter.name,
        translated_count=translated_count,
        failed_count=failed_count,
        errors=errors,
    )
