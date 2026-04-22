#!/usr/bin/env python3
"""Validate translated EQL rules against Elasticsearch."""

import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
import yaml
from requests.auth import HTTPBasicAuth

BASE_DIR = Path(__file__).parent
TRANSLATED_DIR = BASE_DIR / "sigma_rules" / "translated"
# Use a broad wildcard; allow_no_indices=true means ES validates syntax even if index is empty/missing
INDEX = "logs-*"
PARAMS = {"allow_no_indices": "true", "ignore_unavailable": "true"}
MAX_WORKERS = 20


def load_config() -> dict:
    with open(BASE_DIR / "config.yaml", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    es = raw.get("elasticsearch", {})
    return {
        "host": es.get("host", "").rstrip("/"),
        "user": es.get("user", ""),
        "password": es.get("password", ""),
    }


def validate_rule(rule_path: Path, session: requests.Session, es_host: str) -> dict:
    query_text = rule_path.read_text(encoding="utf-8").strip()
    # EQL files may contain multiple queries separated by blank lines; test the first
    first_query = query_text.split("\n\n")[0].strip()
    url = f"{es_host}/{INDEX}/_eql/search"
    body = {"query": first_query, "size": 0}
    try:
        r = session.post(url, json=body, params=PARAMS, timeout=15)
        if r.status_code in (200, 404):
            return {"path": rule_path, "ok": True, "status": r.status_code}
        err = r.json().get("error", {})
        reason = (
            err.get("caused_by", {}).get("reason")
            or (err.get("root_cause") or [{}])[0].get("reason")
            or err.get("reason")
            or r.text[:200]
        )
        return {"path": rule_path, "ok": False, "status": r.status_code, "reason": reason}
    except Exception as exc:
        return {"path": rule_path, "ok": False, "status": 0, "reason": str(exc)}


def main():
    cfg = load_config()
    rule_files = sorted(TRANSLATED_DIR.rglob("*.eql"))
    total = len(rule_files)
    if total == 0:
        print("No .eql files found under", TRANSLATED_DIR)
        sys.exit(1)

    print(f"Validating {total} EQL rules against {cfg['host']} ...")

    session = requests.Session()
    session.auth = HTTPBasicAuth(cfg["user"], cfg["password"])
    session.headers.update({"Content-Type": "application/json"})
    session.verify = True

    passed, failed = [], []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(validate_rule, p, session, cfg["host"]): p for p in rule_files}
        done = 0
        for future in as_completed(futures):
            done += 1
            result = future.result()
            if result["ok"]:
                passed.append(result)
            else:
                failed.append(result)
            if done % 200 == 0 or done == total:
                print(f"  {done}/{total} checked — {len(passed)} ok, {len(failed)} failed")

    print(f"\n{'='*60}")
    print(f"RESULTS: {len(passed)} passed  |  {len(failed)} failed  |  {total} total")
    print(f"{'='*60}")

    if failed:
        print(f"\nFailed rules ({len(failed)}):")
        for r in sorted(failed, key=lambda x: str(x["path"])):
            rel = r["path"].relative_to(BASE_DIR)
            print(f"  [{r['status']}] {rel}")
            print(f"         {r['reason']}")

        # Write detailed failure report
        report_path = BASE_DIR / "eql_validation_failures.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(
                [{"file": str(r["path"].relative_to(BASE_DIR)), "status": r["status"], "reason": r["reason"]} for r in failed],
                f, indent=2,
            )
        print(f"\nDetailed failure report saved to: {report_path}")

    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
