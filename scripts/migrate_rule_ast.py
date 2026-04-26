#!/usr/bin/env python3
"""
Migrate rule_ast/{sigma,elastic}/*.json → catalogs/{sigma,elastic}/ast/<uuid>.json

The rule_ast format is the pre-refactor format (source, name, category, conditions, raw_query).
The catalogs/ast format is the RuleAST format (id, catalog, name, description, severity,
mitre_techniques, event_categories, conditions, raw_query, language, translated_query,
source_path, metadata).
"""
from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path

ROOT = Path(__file__).parent.parent

# risk_score → severity mapping for Elastic rules
def _risk_to_severity(risk: int) -> str:
    if risk >= 73:
        return "critical"
    if risk >= 47:
        return "high"
    if risk >= 21:
        return "medium"
    return "low"


# Extract MITRE technique IDs from tags like "Tactic: TA0001" or "Technique: T1059"
def _mitre_from_tags(tags: list[str]) -> list[str]:
    techniques = []
    for tag in tags:
        lower = tag.lower()
        if "t1" in lower or "ta0" in lower:
            # Pull out things that look like T1059.001 or TA0002
            import re
            hits = re.findall(r'(t\d{4}(?:\.\d{3})?|ta\d{4})', lower)
            for h in hits:
                key = f"attack.{h}"
                if key not in techniques:
                    techniques.append(key)
    return techniques


def migrate_sigma(src_dir: Path, dst_dir: Path) -> int:
    dst_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for src in src_dir.glob("*.json"):
        try:
            raw = json.loads(src.read_text(encoding="utf-8"))
        except Exception:
            continue

        name = raw.get("name") or src.stem
        rule_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"sigma:{src.stem}"))

        # Normalise conditions — ensure raw_values is present
        conditions = []
        for c in raw.get("conditions", []):
            if not isinstance(c.get("values"), list):
                continue
            conditions.append({
                "field": c.get("field", ""),
                "raw_field": c.get("raw_field", c.get("field", "")),
                "operator": c.get("operator", "=="),
                "values": c["values"],
                "raw_values": c.get("raw_values", c["values"]),
            })

        ast = {
            "id": rule_id,
            "catalog": "sigma",
            "name": name,
            "description": raw.get("description", ""),
            "severity": raw.get("severity", "medium"),
            "mitre_techniques": raw.get("mitre_techniques", []),
            "event_categories": [raw["category"]] if raw.get("category") else [],
            "conditions": conditions,
            "raw_query": raw.get("raw_query", ""),
            "language": raw.get("language", "sigma"),
            "translated_query": raw.get("translated_query"),
            "source_path": raw.get("sigma_path", str(src)),
            "metadata": {},
        }

        (dst_dir / f"{rule_id}.json").write_text(
            json.dumps(ast, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        count += 1
    return count


def migrate_elastic(src_dir: Path, dst_dir: Path) -> int:
    dst_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for src in src_dir.glob("*.json"):
        try:
            raw = json.loads(src.read_text(encoding="utf-8"))
        except Exception:
            continue

        name = raw.get("name") or src.stem
        rule_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"elastic:{raw.get('slug', src.stem)}"))

        risk = raw.get("risk_score", 21)
        severity = _risk_to_severity(int(risk) if isinstance(risk, (int, float)) else 21)
        mitre = _mitre_from_tags(raw.get("tags", []))

        conditions = []
        for c in raw.get("conditions", []):
            if not isinstance(c.get("values"), list):
                continue
            conditions.append({
                "field": c.get("field", ""),
                "raw_field": c.get("raw_field", c.get("field", "")),
                "operator": c.get("operator", "=="),
                "values": c["values"],
                "raw_values": c.get("raw_values", c["values"]),
            })

        ast = {
            "id": rule_id,
            "catalog": "elastic",
            "name": name,
            "description": raw.get("description", ""),
            "severity": severity,
            "mitre_techniques": mitre,
            "event_categories": [raw["category"]] if raw.get("category") else [],
            "conditions": conditions,
            "raw_query": raw.get("raw_query", ""),
            "language": raw.get("language", "eql"),
            "translated_query": raw.get("translated_query"),
            "source_path": raw.get("elastic_path", str(src)),
            "metadata": {"risk_score": risk, "tags": raw.get("tags", [])},
        }

        (dst_dir / f"{rule_id}.json").write_text(
            json.dumps(ast, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        count += 1
    return count


if __name__ == "__main__":
    rule_ast = ROOT / "rule_ast"
    catalogs = ROOT / "catalogs"

    # Clear old demo data
    for catalog in ("sigma", "elastic"):
        ast_dir = catalogs / catalog / "ast"
        if ast_dir.exists():
            shutil.rmtree(ast_dir)

    sigma_count = migrate_sigma(rule_ast / "sigma", catalogs / "sigma" / "ast")
    elastic_count = migrate_elastic(rule_ast / "elastic", catalogs / "elastic" / "ast")

    print(f"Migrated {sigma_count} Sigma rules → catalogs/sigma/ast/")
    print(f"Migrated {elastic_count} Elastic rules → catalogs/elastic/ast/")
    print("Done.")
