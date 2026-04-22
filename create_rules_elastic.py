#!/usr/bin/env python3
"""
Push translated EQL rules to Kibana Detection Engine.

Before creating each rule the EQL is executed as a real search against the
exact same index patterns the rule will use (ignore_unavailable=true, NO
allow_no_indices).  Any rule whose query returns a 400 is skipped — this
catches both syntax errors and fields that don't exist in the target indices.

Validation and creation are parallelised for speed.
"""

import base64
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
import yaml
from requests.auth import HTTPBasicAuth

BASE_DIR = Path(__file__).parent
TRANSLATED_DIR = BASE_DIR / "sigma_rules" / "translated"
SIGMA_ROOT = BASE_DIR / "sigma_rules"

# Index patterns the rules will search — validation runs against these exact
# patterns so unknown fields are caught before the rule reaches Kibana.
INDEX_PATTERNS = [
    "logs-endpoint.events.process-*",
    "logs-endpoint.events.network-*",
    "logs-endpoint.events.file-*",
    "logs-endpoint.events.registry-*",
    "logs-endpoint.events.library-*",
    "logs-windows.sysmon_operational-*",
    "winlogbeat-*",
]
VALIDATION_INDEX = ",".join(INDEX_PATTERNS)

EXCLUDE_PATH_FRAGMENTS = [
    "bitbucket",
    "opencanary",
]

_SEVERITY_MAP = {
    "critical":      ("critical", 99),
    "high":          ("high",     73),
    "medium":        ("medium",   47),
    "low":           ("low",      21),
    "informational": ("low",      21),
}

MAX_WORKERS = 20


def load_config() -> dict:
    with open(BASE_DIR / "config.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


def make_session(user: str, password: str) -> requests.Session:
    s = requests.Session()
    s.auth = HTTPBasicAuth(user, password)
    s.headers.update({"Content-Type": "application/json"})
    s.verify = True
    return s


def make_kibana_headers(user: str, password: str) -> dict:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {
        "Authorization": f"Basic {token}",
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
    }


def run_eql_query(query: str, es_host: str, session: requests.Session) -> tuple[bool, str]:
    """
    Execute the EQL query against the exact index patterns the rule will use.
    ignore_unavailable=true handles missing indices (e.g. winlogbeat-*).
    No allow_no_indices — field existence is checked against the real schema.
    Returns (ok, error_reason).
    """
    try:
        r = session.post(
            f"{es_host}/{VALIDATION_INDEX}/_eql/search",
            json={"query": query, "size": 0},
            params={"ignore_unavailable": "true"},
            timeout=15,
        )
        if r.status_code == 200:
            return True, ""
        err = r.json().get("error", {})
        reason = (
            err.get("caused_by", {}).get("reason")
            or (err.get("root_cause") or [{}])[0].get("reason")
            or err.get("reason")
            or r.text[:200]
        )
        return False, reason
    except Exception as exc:
        return False, str(exc)


def load_rule_payload(eql_path: Path, product_filter: str | None = None) -> dict | None:
    """
    Build a Kibana rule payload from a validated .eql and its Sigma source.
    Returns None if the product filter doesn't match or metadata can't be loaded.
    """
    relative = eql_path.relative_to(TRANSLATED_DIR)
    sigma_path = SIGMA_ROOT / relative.with_suffix(".yml")
    if not sigma_path.exists():
        return None
    try:
        meta = yaml.safe_load(sigma_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return None

    if product_filter:
        logsource_product = (meta.get("logsource") or {}).get("product", "")
        if logsource_product.lower() != product_filter.lower():
            return None

    query = eql_path.read_text(encoding="utf-8").strip()
    if not query:
        return None

    level = (meta.get("level") or "medium").lower()
    severity, risk_score = _SEVERITY_MAP.get(level, ("medium", 47))

    raw_tags = meta.get("tags") or []
    tags = [t.replace("attack.", "").upper() for t in raw_tags if isinstance(t, str)]

    return {
        "type": "eql",
        "language": "eql",
        "name": f"(SIGMA) {meta.get('title') or eql_path.stem}",
        "description": (meta.get("description") or eql_path.stem)[:1024],
        "rule_id": str(meta.get("id") or eql_path.stem),
        "enabled": True,
        "risk_score": risk_score,
        "severity": severity,
        "tags": ["SIGMA", *tags][:10],
        "query": query,
        "index": INDEX_PATTERNS,
        "from": "now-6m",
        "interval": "5m",
    }


def create_kibana_rule(payload: dict, kibana_url: str, headers: dict) -> tuple[str, str]:
    """Returns ('created'|'exists'|'failed', detail)."""
    try:
        r = requests.post(
            f"{kibana_url}/api/detection_engine/rules",
            headers=headers,
            json=payload,
            timeout=15,
        )
        if r.status_code in (200, 201):
            return "created", r.json().get("id", "")
        if r.status_code == 409:
            return "exists", ""
        return "failed", f"HTTP {r.status_code}: {r.text[:200]}"
    except Exception as exc:
        return "failed", str(exc)


def validate_worker(args: tuple) -> dict:
    """Runs in a thread pool — validates one rule and returns its status."""
    eql_path, es_host, es_session, product_filter = args
    rel = str(eql_path.relative_to(TRANSLATED_DIR)).replace("\\", "/").lower()

    if any(frag in rel for frag in EXCLUDE_PATH_FRAGMENTS):
        return {"status": "excluded", "path": eql_path}

    payload = load_rule_payload(eql_path, product_filter=product_filter)
    if payload is None:
        return {"status": "filtered", "path": eql_path}

    ok, reason = run_eql_query(payload["query"], es_host, es_session)
    if not ok:
        short = reason.splitlines()[0][:120] if reason else "unknown"
        return {"status": "invalid", "path": eql_path, "name": payload["name"], "reason": short}

    return {"status": "valid", "path": eql_path, "name": payload["name"], "payload": payload}


def main(limit: int = 9999, product: str | None = None) -> None:
    cfg = load_config()
    es_host = cfg["elasticsearch"]["host"].rstrip("/")
    es_session = make_session(cfg["elasticsearch"]["user"], cfg["elasticsearch"]["password"])
    kb_headers = make_kibana_headers(cfg["elasticsearch"]["user"], cfg["elasticsearch"]["password"])
    kibana_url = cfg["kibana"]["url"].rstrip("/")

    all_eql = sorted(TRANSLATED_DIR.rglob("*.eql"))
    filter_note = f"product={product}" if product else "all products"
    print(f"Validated rules on disk : {len(all_eql)}")
    print(f"Filter : {filter_note}  |  excluding : {', '.join(EXCLUDE_PATH_FRAGMENTS)}")
    print(f"Validation index : {VALIDATION_INDEX[:80]}...")
    print(f"Workers : {MAX_WORKERS}\n")

    # --- Phase 1: parallel EQL validation ---
    print("Phase 1/2  validating EQL against cluster...")
    valid_payloads = []
    excluded = filtered = invalid = 0

    work = [(p, es_host, es_session, product) for p in all_eql]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(validate_worker, w): w for w in work}
        done = 0
        for future in as_completed(futures):
            done += 1
            r = future.result()
            if r["status"] == "excluded":
                excluded += 1
            elif r["status"] == "filtered":
                filtered += 1
            elif r["status"] == "invalid":
                invalid += 1
            else:
                valid_payloads.append(r["payload"])
            if done % 200 == 0 or done == len(work):
                print(f"  {done}/{len(work)}  valid so far: {len(valid_payloads)}")

    valid_payloads = valid_payloads[:limit]
    print(f"\nValid rules to push : {len(valid_payloads)}")

    # --- Phase 2: parallel Kibana rule creation ---
    print("\nPhase 2/2  creating rules in Kibana...")
    created = skipped = failed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(create_kibana_rule, p, kibana_url, kb_headers): p
            for p in valid_payloads
        }
        for future in as_completed(futures):
            payload = futures[future]
            status, detail = future.result()
            if status == "created":
                print(f"  [OK]  {payload['name']}")
                created += 1
            elif status == "exists":
                skipped += 1
            else:
                print(f"  [FAIL] {payload['name']}  — {detail}")
                failed += 1

    print(f"\n{'='*60}")
    print(f"Created  : {created}")
    print(f"Dup/skip : {skipped}")
    print(f"Excluded : {excluded}  ({', '.join(EXCLUDE_PATH_FRAGMENTS)})")
    print(f"Filtered : {filtered}  (wrong product / no source YAML)")
    print(f"Invalid  : {invalid}  (EQL failed against target indices)")
    print(f"Failed   : {failed}  (Kibana API error)")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--limit", type=int, default=9999,
                        help="Max rules to push (default: all)")
    parser.add_argument("-p", "--product", default="windows",
                        help="Logsource product filter (default: windows)")
    args = parser.parse_args()
    main(limit=args.limit, product=args.product)
