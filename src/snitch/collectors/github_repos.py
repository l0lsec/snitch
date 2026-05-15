"""Discover Git repositories cloned under common dev directories."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from snitch.core.findings import Ecosystem, InstalledPackage
from snitch.core.orchestrator import Collector

from .base import run_command

log = logging.getLogger("snitch.collectors.github_repos")

DEFAULT_ROOTS = (
    "~/code",
    "~/projects",
    "~/repos",
    "~/src",
    "~/tools",
    "~/work",
    "~/dev",
)
MAX_DEPTH = 4


class GithubReposCollector(Collector):
    ecosystem = Ecosystem.GIT

    def collect(self) -> list[InstalledPackage]:
        results: list[InstalledPackage] = []
        seen: set[Path] = set()
        for root in DEFAULT_ROOTS:
            base = Path(os.path.expanduser(root))
            if not base.exists():
                continue
            for repo in self._find_repos(base, MAX_DEPTH):
                if repo in seen:
                    continue
                seen.add(repo)
                results.append(self._record(repo))
        return results

    def _find_repos(self, base: Path, max_depth: int) -> list[Path]:
        out: list[Path] = []
        stack: list[tuple[Path, int]] = [(base, 0)]
        while stack:
            cur, depth = stack.pop()
            try:
                entries = list(cur.iterdir())
            except (PermissionError, FileNotFoundError):
                continue
            if (cur / ".git").exists():
                out.append(cur)
                continue  # don't descend into a repo
            if depth >= max_depth:
                continue
            for e in entries:
                if e.is_dir() and not e.name.startswith("."):
                    stack.append((e, depth + 1))
        return out

    def _record(self, repo: Path) -> InstalledPackage:
        remote = self._remote_url(repo)
        last_commit = self._last_commit(repo)
        return InstalledPackage(
            ecosystem=Ecosystem.GIT,
            name=remote or repo.name,
            version=last_commit,
            location=repo,
            repo_url=remote,
            extras={
                "path": str(repo),
                "remote": remote,
                "last_commit": last_commit,
            },
        )

    @staticmethod
    def _remote_url(repo: Path) -> str | None:
        rc, out, _ = run_command(
            ["git", "-C", str(repo), "config", "--get", "remote.origin.url"],
            timeout=10,
        )
        return out.strip() if rc == 0 and out.strip() else None

    @staticmethod
    def _last_commit(repo: Path) -> str | None:
        rc, out, _ = run_command(
            ["git", "-C", str(repo), "rev-parse", "--short", "HEAD"],
            timeout=10,
        )
        return out.strip() if rc == 0 and out.strip() else None
