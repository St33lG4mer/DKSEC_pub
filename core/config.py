# core/config.py
"""Config loader — no Streamlit dependency."""
from __future__ import annotations

import base64
import os
from pathlib import Path

import yaml

BASE_DIR = Path(__file__).parent.parent

_DEFAULTS: dict = {
    "kibana": {"url": ""},
    "elasticsearch": {"host": "", "user": "", "password": ""},
    "sigma": {
        "input_dirs": [],
        "output_dir": "catalogs/sigma/raw",
        "failed_log": "catalogs/sigma/failed/failed.log",
        "status_filter": ["stable", "test"],
    },
}


def load_config(path: Path | None = None) -> dict:
    """
    Load configuration in priority order:
    1. Environment variable overrides (DKSEC_KIBANA_URL, etc.)
    2. config.yaml at `path` (defaults to BASE_DIR/config.yaml)
    3. Built-in defaults

    Returns a merged dict — always safe to call even if no config file exists.
    """
    cfg_path = path if path is not None else BASE_DIR / "config.yaml"

    config: dict = {
        "kibana": dict(_DEFAULTS["kibana"]),
        "elasticsearch": dict(_DEFAULTS["elasticsearch"]),
        "sigma": dict(_DEFAULTS["sigma"]),
    }

    if cfg_path.exists():
        try:
            loaded = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
            _deep_merge(config, loaded)
        except Exception:
            pass

    # Environment variable overrides
    if url := os.environ.get("DKSEC_KIBANA_URL"):
        config["kibana"]["url"] = url
    if host := os.environ.get("DKSEC_ES_HOST"):
        config["elasticsearch"]["host"] = host
    if user := os.environ.get("DKSEC_ES_USER"):
        config["elasticsearch"]["user"] = user
    if password := os.environ.get("DKSEC_ES_PASSWORD"):
        config["elasticsearch"]["password"] = password

    return config


def _deep_merge(base: dict, override: dict) -> None:
    """Merge `override` into `base` in-place, recursing into nested dicts."""
    for key, val in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(val, dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val


def kibana_headers(user: str, password: str) -> dict:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {
        "Authorization": f"Basic {token}",
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
    }
