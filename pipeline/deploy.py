"""
Step 3 / Step 6 of the DKSec pipeline: deploy rules to a SIEM via the adapter.

Two modes:
  - "test":      Deploy candidate rules tagged 'dksec-test' so they co-exist
                 with existing SIEM rules during the attack chain run. The
                 adapter is responsible for applying the tag.
  - "permanent": Deploy confirmed unique rules as permanent detections and
                 (optionally) clean up 'dksec-test' tagged rules. The adapter
                 handles cleanup.

Usage:
    from adapters.elastic.adapter import ElasticAdapter
    from pipeline.deploy import deploy_rules
    from storage.rule_store import RuleStore
    from pathlib import Path

    adapter = ElasticAdapter(kibana_url="https://kibana.lab.local", api_key="...")
    store = RuleStore(Path("catalogs"))
    rules = store.load_all("sigma")
    result = deploy_rules(adapter, rules, client=None, mode="test")
    print(f"Deployed {result.deployed_count} rules ({result.failed_count} failed)")
"""
from __future__ import annotations

from dataclasses import dataclass, field

from adapters.base import BaseAdapter
from core.ast_model import RuleAST


@dataclass
class DeployResult:
    """Summary of a single deploy run."""
    catalog: str
    mode: str            # "test" | "permanent"
    deployed_count: int
    failed_count: int
    errors: list[str] = field(default_factory=list)


def deploy_rules(
    adapter: BaseAdapter,
    rules: list[RuleAST],
    client,
    mode: str = "test",
) -> DeployResult:
    """
    Push rules to a SIEM via adapter.deploy().

    Per-rule failures are caught and recorded — deploy_rules never raises.
    It is the adapter's responsibility to apply the 'dksec-test' tag when
    mode='test' and to clean up tagged rules when mode='permanent'.

    Args:
        adapter:  A BaseAdapter with deploy() implemented
        rules:    List of RuleAST objects to deploy
        client:   SIEM API client (passed through to adapter.deploy())
        mode:     "test" (temporary, tagged) or "permanent"

    Returns:
        DeployResult with deployed_count, failed_count, and errors
    """
    deployed_count = 0
    failed_count = 0
    errors: list[str] = []

    for rule in rules:
        try:
            adapter.deploy(rule, client)
            deployed_count += 1
        except Exception as exc:  # noqa: BLE001
            failed_count += 1
            errors.append(f"{rule.id}: {exc}")

    return DeployResult(
        catalog=adapter.name,
        mode=mode,
        deployed_count=deployed_count,
        failed_count=failed_count,
        errors=errors,
    )
