#!/usr/bin/env python3
"""
Create all curated rules in Elastic Detection Engine from scratch.

Reads config.yaml for connection details.
Uses rule_ast/ for rule definitions and rule_ast/rule_decisions.md for the keep/skip lists.

What gets created:
  - 1532 Elastic rules marked KEEP in rule_decisions.md (recreated from AST files)
  - ~1894 Sigma rules (all sigma AST files MINUS the 296 marked Skip in the report)
  - ML rules (no query language) are skipped — they require manual setup

Usage:
  python create_all_rules.py                # create everything
  python create_all_rules.py --elastic-only # only Elastic keep rules
  python create_all_rules.py --sigma-only   # only Sigma rules
  python create_all_rules.py --dry-run      # print what would be created, no API calls
"""

import argparse
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
import yaml
from requests.auth import HTTPBasicAuth

BASE_DIR = Path(__file__).parent
ELASTIC_AST_DIR = BASE_DIR / "rule_ast" / "elastic"
SIGMA_AST_DIR   = BASE_DIR / "rule_ast" / "sigma"
REPORT_PATH     = BASE_DIR / "rule_ast" / "comparison_report.md"
DECISIONS_PATH  = BASE_DIR / "rule_ast" / "rule_decisions.md"

MAX_WORKERS = 20

# Index patterns used for all EQL/query rules
INDEX_PATTERNS = [
    "logs-endpoint.events.process-*",
    "logs-endpoint.events.network-*",
    "logs-endpoint.events.file-*",
    "logs-endpoint.events.registry-*",
    "logs-endpoint.events.library-*",
    "logs-windows.sysmon_operational-*",
    "winlogbeat-*",
]

_RISK_TO_SEVERITY = {
    99: "critical",
    73: "high",
    47: "medium",
    21: "low",
}


# ── Config & HTTP ────────────────────────────────────────────────────────────

def load_config() -> dict:
    path = BASE_DIR / "config.yaml"
    if not path.exists():
        sys.exit(f"ERROR: config.yaml not found at {path}")
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def make_kibana_headers(user: str, password: str) -> dict:
    import base64
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {
        "Authorization": f"Basic {token}",
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
    }


# ── Risk score → severity ────────────────────────────────────────────────────

def risk_to_severity(risk: int) -> str:
    if risk >= 73:
        return "high" if risk < 99 else "critical"
    if risk >= 47:
        return "medium"
    return "low"


# ── Rule payload builders ────────────────────────────────────────────────────

def build_elastic_payload(ast: dict) -> dict | None:
    """
    Build a Kibana Detection Rule payload from an Elastic AST file.
    Returns None for ML rules (no language/query) and unsupported types.
    """
    lang = ast.get("language", "")
    query = ast.get("raw_query", "").strip()
    name = ast.get("name", ast.get("slug", "Unknown"))
    slug = ast.get("slug", "")
    risk = ast.get("risk_score", 47)
    tags = ast.get("tags", [])

    if not lang or not query:
        return None  # ML / threshold rule — skip

    if lang == "eql":
        rule_type = "eql"
    elif lang in ("kuery", "lucene"):
        rule_type = "query"
    elif lang == "esql":
        rule_type = "esql"
    else:
        return None  # unknown language

    payload: dict = {
        "name": f"(ELASTIC) {name}",
        "description": name,
        "rule_id": slug,
        "enabled": True,
        "risk_score": risk,
        "severity": risk_to_severity(risk),
        "tags": ["ELASTIC", *tags][:20],
        "type": rule_type,
        "language": lang,
        "query": query,
        "from": "now-6m",
        "interval": "5m",
    }

    # index patterns not needed for esql
    if lang != "esql":
        payload["index"] = INDEX_PATTERNS

    return payload


def build_sigma_payload(ast: dict) -> dict | None:
    """
    Build a Kibana Detection Rule payload from a Sigma AST file.
    All Sigma rules were translated to EQL.
    """
    query = ast.get("raw_query", "").strip()
    slug = ast.get("name", "")  # sigma AST uses 'name' as the slug
    if not query or not slug:
        return None

    # Try to get risk/severity from the AST; default to medium
    risk = ast.get("risk_score", 47)
    tags = ast.get("tags", [])

    # Readable display name: strip category prefix (everything before _win_ or linux_ etc.)
    display = slug
    for sep in ("_win_", "_linux_", "_macos_", "_network_"):
        if sep in slug:
            display = slug.split(sep, 1)[1]
            break
    display = display.replace("_", " ").title()

    return {
        "name": f"(SIGMA) {display}",
        "description": display,
        "rule_id": f"sigma-{slug}",
        "enabled": True,
        "risk_score": risk,
        "severity": risk_to_severity(risk),
        "tags": ["SIGMA", *tags][:20],
        "type": "eql",
        "language": "eql",
        "query": query,
        "index": INDEX_PATTERNS,
        "from": "now-6m",
        "interval": "5m",
    }


# ── Report parsing ────────────────────────────────────────────────────────────

def parse_skip_sigma_names(report_text: str) -> set[str]:
    """
    Extract sigma display names from the Skip section.
    Returns normalised set (lower + underscores).
    """
    start = report_text.find("## ⏭️ Skip")
    end   = report_text.find("## ⚖️", start + 1)
    section = report_text[start:end] if end != -1 else report_text[start:]

    skip_names = set()
    for line in section.splitlines():
        cells = [c.strip() for c in line.split("|") if c.strip()]
        if len(cells) >= 3:
            try:
                float(cells[2])  # score column sanity check
                name_norm = cells[0].lower().replace(" ", "_")
                skip_names.add(name_norm)
            except ValueError:
                pass
    return skip_names


def parse_keep_elastic_slugs(decisions_text: str) -> set[str]:
    """Extract elastic slugs from rule_decisions.md Section 2 (KEEP)."""
    slugs = set()
    in_keep = False
    for line in decisions_text.splitlines():
        if "## 2. Elastic Rules to KEEP" in line:
            in_keep = True
            continue
        if in_keep and line.startswith("## "):
            break
        if in_keep:
            m = re.search(r"`([a-z0-9_]+)`", line)
            if m:
                slugs.add(m.group(1))
    return slugs


# ── Sigma slug matching ───────────────────────────────────────────────────────

def build_sigma_suffix_index(sigma_files: dict[str, Path]) -> dict[str, list[str]]:
    """
    Build reverse index: suffix_after_win → [full_slug, ...].
    Handles multiple prefix patterns.
    """
    index: dict[str, list[str]] = {}
    for slug in sigma_files:
        suffixes = [slug]  # always index the full slug
        # Strip known category prefixes to get the core name
        for sep in ("_win_", "_linux_", "_macos_", "_network_"):
            if sep in slug:
                suffix = slug.split(sep, 1)[1]
                suffixes.append(suffix)
                break
        for s in suffixes:
            index.setdefault(s, []).append(slug)
    return index


def resolve_skip_slugs(
    skip_names: set[str],
    suffix_index: dict[str, list[str]],
    sigma_files: dict[str, Path],
) -> set[str]:
    """Map skip display names (normalised) to sigma slugs."""
    skip_slugs: set[str] = set()
    unmatched: list[str] = []
    for name in skip_names:
        if name in sigma_files:          # exact slug match
            skip_slugs.add(name)
        elif name in suffix_index:       # suffix match
            skip_slugs.update(suffix_index[name])
        else:
            unmatched.append(name)
    if unmatched:
        print(f"  WARN  {len(unmatched)} Skip sigma rules could not be matched to AST files "
              f"(they may have been imported as Elastic rules already)")
    return skip_slugs


# ── Kibana API ────────────────────────────────────────────────────────────────

def create_rule(payload: dict, kibana_url: str, headers: dict) -> tuple[str, str]:
    """Returns ('created' | 'exists' | 'failed', detail)."""
    try:
        r = requests.post(
            f"{kibana_url}/api/detection_engine/rules",
            headers=headers,
            json=payload,
            timeout=20,
        )
        if r.status_code in (200, 201):
            return "created", r.json().get("id", "")
        if r.status_code == 409:
            return "exists", ""
        return "failed", f"HTTP {r.status_code}: {r.text[:200]}"
    except Exception as exc:
        return "failed", str(exc)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Create curated rules in Elastic Detection Engine")
    parser.add_argument("--elastic-only", action="store_true", help="Only create Elastic KEEP rules")
    parser.add_argument("--sigma-only",   action="store_true", help="Only create Sigma rules")
    parser.add_argument("--dry-run",      action="store_true", help="Print payloads, no API calls")
    args = parser.parse_args()

    cfg        = load_config()
    kibana_url = cfg["kibana"]["url"].rstrip("/")
    headers    = make_kibana_headers(cfg["elasticsearch"]["user"], cfg["elasticsearch"]["password"])

    report_text    = REPORT_PATH.read_text(encoding="utf-8")
    decisions_text = DECISIONS_PATH.read_text(encoding="utf-8") if DECISIONS_PATH.exists() else ""

    # ── Load sigma AST files ──────────────────────────────────────────────────
    sigma_files: dict[str, Path] = {
        f.stem: f for f in SIGMA_AST_DIR.glob("*.json")
    }
    skip_names   = parse_skip_sigma_names(report_text)
    suffix_index = build_sigma_suffix_index(sigma_files)
    skip_slugs   = resolve_skip_slugs(skip_names, suffix_index, sigma_files)

    # ── Load elastic AST files ────────────────────────────────────────────────
    elastic_files: dict[str, Path] = {
        f.stem: f for f in ELASTIC_AST_DIR.glob("*.json")
    }
    keep_slugs = parse_keep_elastic_slugs(decisions_text)
    if not keep_slugs:
        # Fallback: use all elastic files if no decisions file
        keep_slugs = set(elastic_files.keys())
        print("WARN: rule_decisions.md not found or empty — using all Elastic rules as KEEP")

    # ── Build payloads ────────────────────────────────────────────────────────
    payloads: list[tuple[str, dict]] = []  # (label, payload)
    skipped_ml = 0

    if not args.sigma_only:
        elastic_count = 0
        for slug in keep_slugs:
            if slug not in elastic_files:
                continue
            ast = json.loads(elastic_files[slug].read_text(encoding="utf-8"))
            p = build_elastic_payload(ast)
            if p is None:
                skipped_ml += 1
                continue
            payloads.append((f"elastic:{slug}", p))
            elastic_count += 1
        print(f"Elastic rules queued : {elastic_count}  (ML/unsupported skipped: {skipped_ml})")

    if not args.elastic_only:
        sigma_count = 0
        sigma_skipped = 0
        for slug, path in sigma_files.items():
            if slug in skip_slugs:
                sigma_skipped += 1
                continue
            ast = json.loads(path.read_text(encoding="utf-8"))
            p = build_sigma_payload(ast)
            if p is None:
                continue
            payloads.append((f"sigma:{slug}", p))
            sigma_count += 1
        print(f"Sigma rules queued   : {sigma_count}  (skipped as duplicate: {sigma_skipped})")

    print(f"Total to create      : {len(payloads)}")

    if args.dry_run:
        print("\n--- DRY RUN: first 5 payloads ---")
        for label, p in payloads[:5]:
            print(f"\n[{label}]")
            print(json.dumps({k: v for k, v in p.items() if k != "query"}, indent=2))
            print(f"  query: {p['query'][:120]}...")
        return

    # ── Create rules in parallel ──────────────────────────────────────────────
    print(f"\nPushing to {kibana_url} ...")
    created = exists = failed = 0
    failures: list[tuple[str, str]] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(create_rule, p, kibana_url, headers): label
            for label, p in payloads
        }
        done = 0
        for future in as_completed(futures):
            done += 1
            label = futures[future]
            status, detail = future.result()
            if status == "created":
                created += 1
            elif status == "exists":
                exists += 1
            else:
                failed += 1
                failures.append((label, detail))
            if done % 200 == 0 or done == len(payloads):
                print(f"  {done}/{len(payloads)}  created={created}  dup={exists}  fail={failed}")

    print(f"\n{'='*60}")
    print(f"Created  : {created}")
    print(f"Duplicate: {exists}  (already existed, skipped)")
    print(f"Failed   : {failed}")
    print(f"ML/skip  : {skipped_ml}  (ML rules need manual setup in Kibana)")

    if failures:
        print(f"\nFirst {min(10, len(failures))} failures:")
        for label, detail in failures[:10]:
            print(f"  {label}: {detail}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
