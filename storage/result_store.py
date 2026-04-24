# storage/result_store.py
"""Read and write comparison results, decisions, and alerts under output/."""
from __future__ import annotations

import json
from pathlib import Path


class ResultStore:
    """
    File-based store for pipeline output artifacts.
    Layout:
        <base_dir>/overlaps/<a>_vs_<b>.json
        <base_dir>/unique/<a>_vs_<b>.json
        <base_dir>/reports/<a>_vs_<b>_decisions.json
        <base_dir>/alerts/<run_id>.json
    """

    def __init__(self, base_dir: Path) -> None:
        self.base_dir = Path(base_dir)

    def _pair_key(self, a: str, b: str) -> str:
        return f"{a}_vs_{b}"

    def _write(self, subdir: str, filename: str, data: object) -> Path:
        d = self.base_dir / subdir
        d.mkdir(parents=True, exist_ok=True)
        path = d / filename
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def _read(self, subdir: str, filename: str) -> object:
        path = self.base_dir / subdir / filename
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def save_overlaps(self, a: str, b: str, overlaps: list[dict]) -> Path:
        return self._write("overlaps", f"{self._pair_key(a, b)}.json", overlaps)

    def load_overlaps(self, a: str, b: str) -> list[dict]:
        return self._read("overlaps", f"{self._pair_key(a, b)}.json") or []

    def save_unique(self, a: str, b: str, unique: list[dict]) -> Path:
        return self._write("unique", f"{self._pair_key(a, b)}.json", unique)

    def load_unique(self, a: str, b: str) -> list[dict]:
        return self._read("unique", f"{self._pair_key(a, b)}.json") or []

    def save_decisions(self, a: str, b: str, decisions: dict[str, str]) -> Path:
        return self._write("reports", f"{self._pair_key(a, b)}_decisions.json", decisions)

    def load_decisions(self, a: str, b: str) -> dict[str, str]:
        return self._read("reports", f"{self._pair_key(a, b)}_decisions.json") or {}

    def save_alerts(self, run_id: str, alerts: list[dict]) -> Path:
        return self._write("alerts", f"{run_id}.json", alerts)

    def load_alerts(self, run_id: str) -> list[dict]:
        return self._read("alerts", f"{run_id}.json") or []

    def list_alert_runs(self) -> list[str]:
        alerts_dir = self.base_dir / "alerts"
        if not alerts_dir.exists():
            return []
        return [p.stem for p in sorted(alerts_dir.glob("*.json"))]
