# core/sources/git_source.py
"""Clone or pull a git repository and return the local path."""
from __future__ import annotations

from pathlib import Path


class GitSource:
    """
    Clone a git repository to a local path, or pull if it already exists.
    Returns the local path so a FolderSource can walk it.
    """

    def __init__(self, url: str, local_path: Path, ref: str = "HEAD") -> None:
        self.url = url
        self.local_path = Path(local_path)
        self.ref = ref

    def sync(self) -> Path:
        """
        Clone the repo if not present, otherwise pull latest.
        Returns self.local_path after sync.
        Raises RuntimeError on git failure.
        """
        try:
            import git
        except ImportError as e:
            raise ImportError("gitpython is required for GitSource. Run: pip install gitpython") from e

        if self.local_path.exists() and (self.local_path / ".git").exists():
            try:
                repo = git.Repo(self.local_path)
                origin = repo.remotes.origin
                origin.pull()
            except Exception as exc:
                raise RuntimeError(f"Failed to pull {self.url}: {exc}") from exc
        else:
            self.local_path.mkdir(parents=True, exist_ok=True)
            try:
                git.Repo.clone_from(self.url, self.local_path)
            except Exception as exc:
                raise RuntimeError(f"Failed to clone {self.url}: {exc}") from exc

        return self.local_path
