#!/usr/bin/env python3
"""Sigma → EQL translation pipeline for Elastic SIEM."""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml
from requests.auth import HTTPBasicAuth
from sigma.backends.elasticsearch import EqlBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.elasticsearch.windows import ecs_windows

BASE_DIR = Path(__file__).parent
log = logging.getLogger("sigma_translator")

def load_sigma_config(config_path: Path) -> dict:
    with open(config_path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    s = raw.get("sigma", {})
    return {
        "input_dirs": s.get("input_dirs", [
            "sigma_rules/rules",
            "sigma_rules/rules-threat-hunting",
            "sigma_rules/rules-emerging-threats",
        ]),
        "output_dir": s.get("output_dir", "sigma_rules/translated"),
        "failed_log": s.get("failed_log", "sigma_rules/failed/failed.log"),
        "status_filter": set(s.get("status_filter", ["stable", "test"])),
    }


def load_es_config(config_path: Path) -> dict:
    with open(config_path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    es = raw.get("elasticsearch", {})
    return {
        "host": es.get("host", "").rstrip("/"),
        "user": es.get("user", ""),
        "password": es.get("password", ""),
    }



def validate_eql(query: str, es_host: str, session: requests.Session) -> tuple[bool, str]:
    """
    Validate EQL against Elasticsearch real indices.

    Validates against logs-* without allow_no_indices so that field existence
    is checked against the actual cluster schema. Any 400 (syntax error OR
    unknown field) means the rule won't work in this cluster.

    Returns (ok, reason):
      ok=True  → ES returned 200 — rule will work at runtime
      ok=False → ES returned 400 — rule will fail at runtime
    """
    url = f"{es_host}/logs-*/_eql/search"
    try:
        r = session.post(
            url,
            json={"query": query, "size": 0},
            params={"ignore_unavailable": "true"},
            timeout=10,
        )
        if r.status_code == 200:
            return True, ""
        body = r.json()
        error = body.get("error", {})
        reason = (
            error.get("caused_by", {}).get("reason")
            or (error.get("root_cause") or [{}])[0].get("reason")
            or error.get("reason")
            or r.text[:300]
        )
        return False, reason
    except Exception as exc:
        return False, str(exc)


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    cfg = load_sigma_config(BASE_DIR / "config.yaml")
    es_cfg = load_es_config(BASE_DIR / "config.yaml")
    sigma_root = BASE_DIR / "sigma_rules"
    output_dir = BASE_DIR / cfg["output_dir"]
    failed_log_path = BASE_DIR / cfg["failed_log"]
    failed_log_path.parent.mkdir(parents=True, exist_ok=True)

    session = requests.Session()
    session.auth = HTTPBasicAuth(es_cfg["user"], es_cfg["password"])
    session.headers.update({"Content-Type": "application/json"})
    session.verify = True

    backend = EqlBackend(processing_pipeline=ecs_windows())

    translated = 0
    invalid_eql = 0
    failed = 0
    skipped = 0

    with open(failed_log_path, "a", encoding="utf-8") as fail_log:
        fail_log.write(
            f"\n--- Run at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} ---\n"
        )

        for input_dir_rel in cfg["input_dirs"]:
            input_dir = BASE_DIR / input_dir_rel
            if not input_dir.exists():
                log.warning(f"Input dir not found, skipping: {input_dir}")
                continue

            rule_paths = sorted(input_dir.rglob("*.yml"))
            log.info(f"{input_dir_rel}: {len(rule_paths)} rules found")

            for rule_path in rule_paths:
                # Lightweight status check before full sigma parse
                try:
                    with open(rule_path, encoding="utf-8") as f:
                        meta = yaml.safe_load(f)
                    status = (meta or {}).get("status", "")
                    if status not in cfg["status_filter"]:
                        skipped += 1
                        continue
                except Exception as e:
                    fail_log.write(f"{rule_path.name}\tFailed to read YAML: {e}\n")
                    failed += 1
                    continue

                # Mirror path: sigma_rules/rules/windows/foo.yml → sigma_rules/translated/rules/windows/foo.eql
                relative = rule_path.relative_to(sigma_root)
                out_path = output_dir / relative.with_suffix(".eql")

                try:
                    text = rule_path.read_text(encoding="utf-8")
                    collection = SigmaCollection.from_yaml(text)
                    queries = backend.convert(collection)

                    if not queries:
                        fail_log.write(f"{rule_path.name}\tNo output produced (unsupported logsource or condition)\n")
                        failed += 1
                        continue

                    # Validate each generated query; skip rule if any has a syntax error
                    eql_text = "\n\n".join(queries)
                    syntax_ok = True
                    for q in queries:
                        ok, reason = validate_eql(q, es_cfg["host"], session)
                        if not ok:
                            fail_log.write(f"{rule_path.name}\tInvalid EQL: {reason}\n")
                            log.debug(f"Invalid EQL in {rule_path.name}: {reason}")
                            syntax_ok = False
                            break

                    if not syntax_ok:
                        invalid_eql += 1
                        # Remove stale .eql file from a previous run so it can't be used
                        if out_path.exists():
                            out_path.unlink()
                        continue

                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    out_path.write_text(eql_text, encoding="utf-8")
                    translated += 1

                except Exception as e:
                    fail_log.write(f"{rule_path.name}\t{e}\n")
                    failed += 1

    print(f"\nDone.")
    print(f"  Translated  : {translated}  (EQL validated, safe to push to Elastic)")
    print(f"  Invalid EQL : {invalid_eql}  (syntax errors — see {failed_log_path})")
    print(f"  Failed      : {failed}  (translation errors)")
    print(f"  Skipped     : {skipped}  (status not in {sorted(cfg['status_filter'])})")
    print(f"  Output      : {output_dir}")


if __name__ == "__main__":
    main()
