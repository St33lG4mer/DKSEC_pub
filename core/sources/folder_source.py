# core/sources/folder_source.py
"""Walk a local directory and yield file paths or their text content."""
from __future__ import annotations

from pathlib import Path


class FolderSource:
    """Yield file paths from a local directory matching a glob pattern."""

    def __init__(self, path: Path, glob_pattern: str = "**/*.yml") -> None:
        self.path = Path(path)
        self.glob_pattern = glob_pattern

    def iter_paths(self):
        """Yield Path objects for each matching file. Raises FileNotFoundError if dir missing."""
        if not self.path.exists():
            raise FileNotFoundError(f"Source directory not found: {self.path}")
        yield from sorted(self.path.glob(self.glob_pattern))

    def iter_contents(self):
        """Yield (Path, str) tuples of matching files and their UTF-8 text content."""
        for p in self.iter_paths():
            try:
                yield p, p.read_text(encoding="utf-8")
            except Exception:
                continue
