# core/sources/api_source.py
"""Paginate a REST API and yield raw rule dicts."""
from __future__ import annotations

import time
from typing import Iterator

import requests


class ApiSource:
    """
    Paginate a REST API endpoint that returns a JSON list of rules.
    Handles rate limiting (429) with exponential backoff.
    """

    def __init__(
        self,
        base_url: str,
        headers: dict,
        page_param: str = "page",
        per_page_param: str = "per_page",
        per_page: int = 500,
        data_key: str = "data",
        total_key: str = "total",
        timeout: int = 30,
        max_retries: int = 5,
    ) -> None:
        self.base_url = base_url
        self.headers = headers
        self.page_param = page_param
        self.per_page_param = per_page_param
        self.per_page = per_page
        self.data_key = data_key
        self.total_key = total_key
        self.timeout = timeout
        self.max_retries = max_retries

    def iter_rules(self) -> Iterator[dict]:
        """Yield raw rule dicts from the API, paginating until exhausted."""
        page = 1
        fetched = 0
        total = None

        while True:
            params = {self.page_param: page, self.per_page_param: self.per_page}
            resp = self._get_with_retry(params)
            data = resp.json()
            batch = data.get(self.data_key, [])
            if total is None:
                total = data.get(self.total_key, 0)

            yield from batch
            fetched += len(batch)

            if not batch or fetched >= total:
                break
            page += 1

    def _get_with_retry(self, params: dict) -> requests.Response:
        for attempt in range(self.max_retries):
            resp = requests.get(
                self.base_url,
                headers=self.headers,
                params=params,
                timeout=self.timeout,
            )
            if resp.status_code in (429, 500, 502, 503):
                time.sleep(2 ** attempt)
                continue
            if resp.status_code != 200:
                raise RuntimeError(f"API error {resp.status_code}: {resp.text[:200]}")
            return resp
        raise RuntimeError(f"API request failed after {self.max_retries} retries")
