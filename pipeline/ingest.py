# pipeline/ingest.py
"""
Step 1 of the DKSec pipeline: load raw rules from a source via an adapter
and persist them for the translate step.

Usage:
    from adapters.sigma.adapter import SigmaAdapter
    from pipeline.ingest import ingest_catalog
    from storage.rule_store import RuleStore
    from pathlib import Path

    adapter = SigmaAdapter(folder_path="catalogs/sigma/raw")
    store = RuleStore(Path("catalogs"))
    result = ingest_catalog(adapter, store)
    print(f"Ingested {result.raw_count} rules from {result.catalog}")
"""
from __future__ import annotations

from dataclasses import dataclass, field

from adapters.base import BaseAdapter
from storage.rule_store import RuleStore


@dataclass
class IngestResult:
    """Summary of a single catalog ingest run."""
    catalog: str
    raw_count: int
    failed_count: int
    errors: list[str] = field(default_factory=list)


def ingest_catalog(adapter: BaseAdapter, store: RuleStore) -> IngestResult:
    """
    Load raw rules from the adapter's source and persist them.

    Calls adapter.load() to fetch raw rule dicts, then saves them via
    store.save_raw(). If load() raises, returns an IngestResult with the
    error recorded — never propagates exceptions to the caller.

    Args:
        adapter:  A BaseAdapter implementation (Sigma, Elastic, etc.)
        store:    RuleStore pointing at the catalogs/ directory

    Returns:
        IngestResult with raw_count, failed_count, and any errors
    """
    try:
        raws = adapter.load()
    except Exception as exc:  # noqa: BLE001
        return IngestResult(catalog=adapter.name, raw_count=0, failed_count=0, errors=[str(exc)])

    store.save_raw(adapter.name, raws)
    # failed_count is always 0 at ingest level — load() is all-or-nothing
    return IngestResult(catalog=adapter.name, raw_count=len(raws), failed_count=0, errors=[])
