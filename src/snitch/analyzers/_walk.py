"""Shared file-traversal helpers for analyzers.

Walks a package's resolved roots with ``os.walk`` and prunes vendored /
test / build / cache directories so analyzers can't escape into adjacent
``site-packages`` entries or third-party deps and mis-attribute findings.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path

from snitch.core.findings import InstalledPackage

EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        "node_modules",
        "__pycache__",
        ".git",
        ".hg",
        ".svn",
        ".tox",
        ".nox",
        ".venv",
        "venv",
        "env",
        "build",
        "dist",
        "site-packages",
        "test",
        "tests",
        "examples",
        "docs",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".cache",
    }
)


def package_roots(package: InstalledPackage) -> list[Path]:
    """Return the on-disk roots an analyzer should scan for ``package``.

    Prefers ``extras["roots"]`` (set by ``PipCollector`` so we never wander
    into adjacent site-packages). Falls back to ``package.location``.
    """
    raw = (package.extras or {}).get("roots")
    paths: list[Path] = []
    seen: set[str] = set()
    if raw:
        for r in raw:
            try:
                p = Path(r)
            except Exception:
                continue
            if not p.exists():
                continue
            key = str(p)
            if key in seen:
                continue
            seen.add(key)
            paths.append(p)
    elif package.location and package.location.exists():
        paths.append(package.location)
    return paths


def iter_files(
    roots: Iterable[Path],
    suffixes: set[str] | frozenset[str],
    *,
    max_files: int,
    max_bytes: int,
    extra_excluded: Iterable[str] = (),
) -> Iterable[Path]:
    """Yield files under ``roots`` whose suffix matches ``suffixes``.

    - Prunes ``EXCLUDED_DIRS`` (plus ``extra_excluded``) in-place so we never
      descend into vendored deps, caches, or test fixtures.
    - Skips files larger than ``max_bytes``.
    - Stops after ``max_files`` files have been yielded.
    """
    excluded = EXCLUDED_DIRS | set(extra_excluded)
    suffix_set = {s.lower() for s in suffixes}
    yielded = 0
    for root in roots:
        if yielded >= max_files:
            return
        if root.is_file():
            if root.suffix.lower() not in suffix_set:
                continue
            try:
                if root.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue
            yield root
            yielded += 1
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in excluded]
            for fname in filenames:
                fpath = Path(dirpath) / fname
                if fpath.suffix.lower() not in suffix_set:
                    continue
                try:
                    if fpath.stat().st_size > max_bytes:
                        continue
                except OSError:
                    continue
                yield fpath
                yielded += 1
                if yielded >= max_files:
                    return
