"""
DKSec CLI — catalog-agnostic detection rule comparison pipeline.

Usage examples:
    python cli.py ingest --catalog sigma --source folder --path ./sigma-rules
    python cli.py translate --catalog sigma
    python cli.py compare --a sigma --b elastic
    python cli.py decide --a sigma --b elastic
    python cli.py attack --framework sliver
    python cli.py deploy --mode test --catalog sigma --target elastic
    python cli.py run-all --a sigma --b elastic --skip-attack
"""
from __future__ import annotations

import sys
from pathlib import Path

import click

from pipeline.compare import compare_rules
from pipeline.decide import decide as _decide_pipeline
from pipeline.deploy import deploy_rules
from pipeline.ingest import ingest_catalog
from pipeline.translate import translate_catalog
from storage.result_store import ResultStore
from storage.rule_store import RuleStore

_CATALOGS_DIR = Path("catalogs")
_OUTPUT_DIR = Path("output")


def _rule_store() -> RuleStore:
    return RuleStore(_CATALOGS_DIR)


def _result_store() -> ResultStore:
    return ResultStore(_OUTPUT_DIR)


def _make_adapter(catalog: str, source: str, path: str | None, url: str | None = None, config: str | None = None):
    """Instantiate the correct adapter for a catalog/source combination."""
    if catalog == "sigma":
        try:
            from adapters.sigma.adapter import SigmaAdapter
            folder = Path(path) if path else _CATALOGS_DIR / "sigma" / "raw"
            return SigmaAdapter(folder_path=folder)
        except ImportError:
            raise click.ClickException(
                "SigmaAdapter not implemented yet. Create adapters/sigma/adapter.py first."
            )
    if catalog == "elastic":
        try:
            from adapters.elastic.adapter import ElasticAdapter
            return ElasticAdapter()
        except ImportError:
            raise click.ClickException(
                "ElasticAdapter not implemented yet. Create adapters/elastic/adapter.py first."
            )
    raise click.BadParameter(f"Unknown catalog: {catalog!r}. Supported: sigma, elastic")


@click.group()
def cli():
    """DKSec — catalog-agnostic detection rule comparison pipeline."""


@cli.command()
@click.option("--catalog", required=True, help="Catalog name: sigma, elastic")
@click.option(
    "--source", required=True,
    type=click.Choice(["folder", "git", "api"]),
    help="Source type for the catalog",
)
@click.option("--path", default=None, help="Local folder path (for --source folder)")
@click.option("--url", default=None, help="Git URL or API base URL")
@click.option("--config", default="config.yaml", help="Config file path")
def ingest(catalog: str, source: str, path: str | None, url: str | None, config: str):
    """Step 1: Load raw rules from source and persist for translate step."""
    adapter = _make_adapter(catalog, source, path, url, config)
    store = _rule_store()
    result = ingest_catalog(adapter, store)
    if result.errors:
        click.echo(f"[ERROR] Ingest failed: {result.errors[0]}", err=True)
        sys.exit(1)
    click.echo(f"Ingested {result.raw_count} raw rules from catalog '{result.catalog}'")


@cli.command()
@click.option("--catalog", required=True, help="Catalog name: sigma, elastic")
@click.option("--source", default="folder", type=click.Choice(["folder", "git", "api"]))
@click.option("--path", default=None)
def translate(catalog: str, source: str, path: str | None):
    """Step 2: Parse and translate raw rules to canonical RuleAST."""
    adapter = _make_adapter(catalog, source, path, url=None)
    store = _rule_store()
    result = translate_catalog(adapter, store)
    status = "WARNING" if result.failed_count else "OK"
    click.echo(
        f"[{status}] Translated {result.translated_count} rules "
        f"({result.failed_count} failed) for catalog '{result.catalog}'"
    )
    for err in result.errors[:5]:
        click.echo(f"  -> {err}", err=True)


@cli.command()
@click.option("--a", "catalog_a", required=True, help="First catalog (source)")
@click.option("--b", "catalog_b", required=True, help="Second catalog (target SIEM)")
@click.option("--threshold", default=0.15, show_default=True, help="Jaccard similarity threshold")
@click.option("--run-id", default=None, help="Attack chain run ID to include alert data")
def compare(catalog_a: str, catalog_b: str, threshold: float, run_id: str | None):
    """Step 3: Compare two catalogs; report overlaps and unique rules."""
    store = _rule_store()
    result_store = _result_store()
    rules_a = store.load_all(catalog_a)
    rules_b = store.load_all(catalog_b)
    alerts = result_store.load_alerts(run_id) if run_id else None
    result = compare_rules(rules_a, rules_b, alerts=alerts, threshold=threshold)
    overlaps_dicts, unique_a_dicts = result.to_storage_dicts()
    result_store.save_overlaps(catalog_a, catalog_b, overlaps_dicts)
    result_store.save_unique(catalog_a, catalog_b, unique_a_dicts)
    result_store.save_unique(catalog_b, catalog_a, [r.to_dict() for r in result.unique_b])
    click.echo(
        f"Comparison complete [{result.confidence}]  "
        f"Overlaps: {len(result.overlaps)}  "
        f"Unique-A: {len(result.unique_a)}  "
        f"Unique-B: {len(result.unique_b)}"
    )


@cli.command()
@click.option("--a", "catalog_a", required=True)
@click.option("--b", "catalog_b", required=True)
def decide(catalog_a: str, catalog_b: str):
    """Step 4: Generate ADD/SKIP decisions for catalog A rules."""
    store = _rule_store()
    result_store = _result_store()
    rules_a = store.load_all(catalog_a)
    rules_b = store.load_all(catalog_b)
    result = compare_rules(rules_a, rules_b)
    decisions = _decide_pipeline(result)
    result_store.save_decisions(catalog_a, catalog_b, decisions)
    add_count = sum(1 for v in decisions.values() if v == "ADD")
    skip_count = sum(1 for v in decisions.values() if v == "SKIP")
    click.echo(f"Decisions saved — ADD: {add_count}  SKIP: {skip_count}")


@cli.command()
@click.option(
    "--framework", required=True,
    type=click.Choice(["sliver", "atomic", "both"]),
    help="Attack framework to use",
)
@click.option("--run-id", default=None, help="Optional stable run identifier")
def attack(framework: str, run_id: str | None):
    """Step 5: Run MITRE ATT&CK scenarios to generate empirical alert data."""
    from pipeline.attack_chain import run_attack_chain

    result_store = _result_store()
    runners = []

    if framework in ("sliver", "both"):
        from attack.sliver import SliverRunner
        runners.append(SliverRunner())
    if framework in ("atomic", "both"):
        from attack.atomic import AtomicRunner
        runners.append(AtomicRunner())

    chain_result = run_attack_chain(runners, result_store, run_id=run_id)
    status = "WARNING" if chain_result.errors else "OK"
    click.echo(
        f"[{status}] Attack chain complete — "
        f"Scenarios: {chain_result.scenario_count}  "
        f"Alerts: {len(chain_result.alerts)}  "
        f"Run ID: {chain_result.run_id}"
    )
    for err in chain_result.errors[:5]:
        click.echo(f"  -> {err}", err=True)


@cli.command()
@click.option(
    "--mode", required=True,
    type=click.Choice(["test", "permanent"]),
    help="'test' = tagged temporary deploy; 'permanent' = persist unique rules",
)
@click.option("--catalog", required=True, help="Catalog to deploy")
@click.option("--target", required=True, help="Target SIEM (e.g. elastic)")
@click.option("--dry-run", is_flag=True, default=False, help="Print rules without deploying")
def deploy(mode: str, catalog: str, target: str, dry_run: bool):
    """Step 3 (test) / Step 6 (permanent): Deploy rules to SIEM."""
    store = _rule_store()
    rules = store.load_all(catalog)
    if dry_run:
        click.echo(f"Dry-run: would deploy {len(rules)} rules from '{catalog}' to '{target}' [{mode}]")
        return
    adapter = _make_adapter(target, "api", path=None, url=None)
    result = deploy_rules(adapter, rules, client=None, mode=mode)
    status = "WARNING" if result.failed_count else "OK"
    click.echo(
        f"[{status}] Deployed {result.deployed_count} rules "
        f"({result.failed_count} failed) [{mode}] -> {target}"
    )
    for err in result.errors[:5]:
        click.echo(f"  -> {err}", err=True)


@cli.command("run-all")
@click.option("--a", "catalog_a", required=True, help="Source catalog (e.g. sigma)")
@click.option("--b", "catalog_b", required=True, help="SIEM catalog (e.g. elastic)")
@click.option("--skip-attack", is_flag=True, default=False, help="Skip attack chain (logic-only mode)")
@click.option("--continue-on-error", is_flag=True, default=False)
def run_all(catalog_a: str, catalog_b: str, skip_attack: bool, continue_on_error: bool):
    """Run the full pipeline: ingest -> translate -> (attack) -> compare -> decide."""
    store = _rule_store()
    result_store = _result_store()

    click.echo(f"Running pipeline: {catalog_a} vs {catalog_b}")

    for cat in (catalog_a, catalog_b):
        adapter = _make_adapter(cat, "folder", path=None, url=None)
        ingest_result = ingest_catalog(adapter, store)
        click.echo(f"  Ingest '{cat}': {ingest_result.raw_count} rules")

    for cat in (catalog_a, catalog_b):
        adapter = _make_adapter(cat, "folder", path=None, url=None)
        translate_result = translate_catalog(adapter, store)
        click.echo(
            f"  Translate '{cat}': {translate_result.translated_count} rules "
            f"({translate_result.failed_count} failed)"
        )

    alerts = None
    if not skip_attack:
        from pipeline.attack_chain import run_attack_chain
        from attack.sliver import SliverRunner
        chain = run_attack_chain([SliverRunner()], result_store)
        alerts = chain.alerts
        click.echo(f"  Attack chain: {len(alerts)} alerts from {chain.scenario_count} scenarios")
    else:
        click.echo("  Skipping attack chain (--skip-attack); using logic-only comparison")

    rules_a = store.load_all(catalog_a)
    rules_b = store.load_all(catalog_b)
    compare_result = compare_rules(rules_a, rules_b, alerts=alerts)
    overlaps_dicts, unique_a_dicts = compare_result.to_storage_dicts()
    result_store.save_overlaps(catalog_a, catalog_b, overlaps_dicts)
    result_store.save_unique(catalog_a, catalog_b, unique_a_dicts)
    result_store.save_unique(catalog_b, catalog_a, [r.to_dict() for r in compare_result.unique_b])
    click.echo(
        f"  Compare [{compare_result.confidence}]: "
        f"{len(compare_result.overlaps)} overlaps, {len(compare_result.unique_a)} unique-{catalog_a}"
    )

    decisions = _decide_pipeline(compare_result)
    result_store.save_decisions(catalog_a, catalog_b, decisions)
    add_count = sum(1 for v in decisions.values() if v == "ADD")
    click.echo(f"  Decide: {add_count} rules marked ADD")
    click.echo("Pipeline complete. Results in output/")


if __name__ == "__main__":
    cli()
