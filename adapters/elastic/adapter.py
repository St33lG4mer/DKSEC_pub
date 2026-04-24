# adapters/elastic/adapter.py
"""ElasticAdapter — loads Elastic detection rules from Kibana API and normalizes to RuleAST."""
from __future__ import annotations

import time

import requests

from adapters.base import BaseAdapter
from core.ast_model import RuleAST, ValidationResult
from core.normalizer import (
    extract_eql_tokens,
    normalize_elastic_mitre_tag,
    risk_to_severity,
    SEVERITY_TO_RISK,
)


def _kibana_headers(user: str, password: str) -> dict:
    import base64
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {
        "Authorization": f"Basic {token}",
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
    }


class ElasticAdapter(BaseAdapter):
    """
    Adapter for Elastic Security detection rules loaded via Kibana API.

    load()      — paginates /api/detection_engine/rules/_find
    parse()     — converts raw Kibana rule JSON to RuleAST
    translate() — no-op: Elastic rules are already EQL; copies raw_query → translated_query
    validate()  — validates EQL against ES cluster (requires es_host)
    deploy()    — creates/updates rule in Kibana
    """

    name = "elastic"
    source_type = "api"

    def __init__(
        self,
        kibana_url: str,
        user: str,
        password: str,
        es_host: str = "",
    ) -> None:
        self.kibana_url = kibana_url.rstrip("/")
        self.user = user
        self.password = password
        self.es_host = es_host.rstrip("/")

    def load(self) -> list[dict]:
        """
        Paginate Kibana detection engine API.
        Returns list of raw rule dicts.
        Raises RuntimeError on non-200/non-retryable response.
        """
        headers = _kibana_headers(self.user, self.password)
        rules: list[dict] = []
        page, per_page = 1, 500

        while True:
            resp = None
            for attempt in range(5):
                resp = requests.get(
                    f"{self.kibana_url}/api/detection_engine/rules/_find",
                    headers=headers,
                    params={"page": page, "per_page": per_page},
                    timeout=30,
                )
                if resp.status_code in (429, 500):
                    time.sleep(2 ** attempt)
                    continue
                break

            if resp.status_code not in (200,):
                raise RuntimeError(f"Kibana API error {resp.status_code}: {resp.text[:200]}")

            data = resp.json()
            batch = data.get("data", [])
            rules.extend(batch)
            if len(rules) >= data.get("total", 0) or not batch:
                break
            page += 1

        return rules

    def parse(self, raw: dict) -> RuleAST:
        """
        Convert a raw Kibana rule dict to a canonical RuleAST.
        translated_query is always None at this stage.
        """
        risk = raw.get("risk_score", 47)
        severity = risk_to_severity(risk)

        raw_tags: list[str] = [t for t in (raw.get("tags") or []) if isinstance(t, str)]
        mitre_techniques: list[str] = []
        for tag in raw_tags:
            norm = normalize_elastic_mitre_tag(tag)
            if norm:
                mitre_techniques.append(norm)

        query = raw.get("query", "")
        event_categories: list[str] = []
        if query:
            tokens = extract_eql_tokens(query)
            event_categories = [t.replace("@cat:", "") for t in tokens if t.startswith("@cat:")]

        rule_id = raw.get("rule_id") or raw.get("id") or RuleAST.new_id()

        return RuleAST(
            id=rule_id,
            catalog="elastic",
            name=raw.get("name", ""),
            description=raw.get("description", ""),
            severity=severity,
            mitre_techniques=mitre_techniques,
            event_categories=event_categories,
            conditions=[],
            raw_query=query,
            language=raw.get("type", "eql"),
            translated_query=None,
            source_path=f"{self.kibana_url}/api/detection_engine/rules/_find",
            metadata={
                "rule_id": raw.get("rule_id", ""),
                "enabled": raw.get("enabled", True),
                "tags": raw_tags,
                "author": raw.get("author", []),
                "created_at": raw.get("created_at", ""),
                "updated_at": raw.get("updated_at", ""),
            },
        )

    def translate(self, ast: RuleAST) -> RuleAST:
        """Elastic rules are already EQL — copy raw_query to translated_query."""
        ast.translated_query = ast.raw_query
        return ast

    def validate(self, ast: RuleAST) -> ValidationResult:
        """
        Validate EQL against Elasticsearch /logs-*/_eql/search endpoint.
        Returns ValidationResult(valid=False, category="config_error") if es_host not set.
        """
        if not self.es_host:
            return ValidationResult(
                valid=False,
                error="No Elasticsearch host configured",
                category="config_error",
            )
        query = ast.translated_query or ast.raw_query
        if not query:
            return ValidationResult(
                valid=False,
                error="No query to validate",
                category="config_error",
            )
        url = f"{self.es_host}/logs-*/_eql/search"
        try:
            session = requests.Session()
            session.auth = (self.user, self.password)
            session.headers.update({"Content-Type": "application/json"})
            r = session.post(
                url,
                json={"query": query, "size": 0},
                params={"ignore_unavailable": "true"},
                timeout=10,
            )
            if r.status_code == 200:
                return ValidationResult(valid=True)
            body = r.json()
            error = body.get("error", {})
            reason = (
                error.get("caused_by", {}).get("reason")
                or (error.get("root_cause") or [{}])[0].get("reason")
                or error.get("reason")
                or r.text[:300]
            )
            return ValidationResult(valid=False, error=reason, category="eql_error")
        except Exception as exc:
            return ValidationResult(valid=False, error=str(exc), category="connection_error")

    def deploy(self, ast: RuleAST, client=None) -> bool:
        """
        Create or update a detection rule in Kibana.
        Returns True on success (HTTP 200 or 201), False otherwise.
        """
        headers = _kibana_headers(self.user, self.password)
        rule_body: dict = {
            "name": ast.name,
            "description": ast.description,
            "risk_score": SEVERITY_TO_RISK.get(ast.severity, 47),
            "severity": ast.severity,
            "type": ast.language,
            "query": ast.translated_query or ast.raw_query,
            "enabled": True,
            "tags": ast.mitre_techniques,
        }
        if ast.metadata.get("rule_id"):
            rule_body["rule_id"] = ast.metadata["rule_id"]

        resp = requests.post(
            f"{self.kibana_url}/api/detection_engine/rules",
            headers=headers,
            json=rule_body,
            timeout=30,
        )
        return resp.status_code in (200, 201)
