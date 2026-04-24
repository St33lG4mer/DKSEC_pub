# tests/core/test_config.py
import os
from pathlib import Path

import pytest
import yaml


def test_load_config_from_file(tmp_path):
    from core.config import load_config

    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        yaml.dump({
            "kibana": {"url": "https://kibana.example.com"},
            "elasticsearch": {"host": "https://es.example.com", "user": "elastic", "password": "secret"},
        }),
        encoding="utf-8",
    )
    config = load_config(cfg_file)
    assert config["kibana"]["url"] == "https://kibana.example.com"
    assert config["elasticsearch"]["user"] == "elastic"


def test_load_config_returns_defaults_when_missing(tmp_path):
    from core.config import load_config

    config = load_config(tmp_path / "nonexistent.yaml")
    assert "kibana" in config
    assert "elasticsearch" in config
    assert config["kibana"]["url"] == ""


def test_load_config_env_override(tmp_path, monkeypatch):
    from core.config import load_config

    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        yaml.dump({"kibana": {"url": "https://original.example.com"}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("DKSEC_KIBANA_URL", "https://override.example.com")
    config = load_config(cfg_file)
    assert config["kibana"]["url"] == "https://override.example.com"


def test_kibana_headers():
    from core.config import kibana_headers

    headers = kibana_headers("elastic", "password123")
    assert "Authorization" in headers
    assert headers["Authorization"].startswith("Basic ")
    assert headers["kbn-xsrf"] == "true"


def test_load_config_does_not_mutate_defaults(tmp_path):
    from core.config import load_config, _DEFAULTS

    config = load_config(tmp_path / "nonexistent.yaml")
    config["sigma"]["input_dirs"].append("mutated")
    
    config2 = load_config(tmp_path / "nonexistent.yaml")
    assert config2["sigma"]["input_dirs"] == []
