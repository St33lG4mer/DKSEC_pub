# tests/core/sources/test_folder_source.py
from pathlib import Path

import pytest

from core.sources.folder_source import FolderSource


def test_folder_source_finds_files(tmp_path):
    (tmp_path / "rule1.yml").write_text("title: Rule 1\n", encoding="utf-8")
    (tmp_path / "rule2.yml").write_text("title: Rule 2\n", encoding="utf-8")
    (tmp_path / "readme.txt").write_text("ignore me\n", encoding="utf-8")

    source = FolderSource(path=tmp_path, glob_pattern="*.yml")
    paths = list(source.iter_paths())

    assert len(paths) == 2
    assert all(p.suffix == ".yml" for p in paths)


def test_folder_source_recursive(tmp_path):
    subdir = tmp_path / "sub"
    subdir.mkdir()
    (tmp_path / "a.yml").write_text("", encoding="utf-8")
    (subdir / "b.yml").write_text("", encoding="utf-8")

    source = FolderSource(path=tmp_path, glob_pattern="**/*.yml")
    paths = list(source.iter_paths())
    assert len(paths) == 2


def test_folder_source_missing_path_raises(tmp_path):
    source = FolderSource(path=tmp_path / "nonexistent", glob_pattern="*.yml")
    with pytest.raises(FileNotFoundError):
        list(source.iter_paths())


def test_folder_source_iter_contents(tmp_path):
    (tmp_path / "rule.yml").write_text("title: Test\n", encoding="utf-8")
    source = FolderSource(path=tmp_path, glob_pattern="*.yml")
    items = list(source.iter_contents())
    assert len(items) == 1
    path, content = items[0]
    assert "title: Test" in content
