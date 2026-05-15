"""Discover VS Code, Cursor, and VSCodium extensions."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from snitch.core.findings import Ecosystem, InstalledPackage
from snitch.core.orchestrator import Collector

log = logging.getLogger("snitch.collectors.vscode")

EXT_DIRS = (
    "~/.cursor/extensions",
    "~/.vscode/extensions",
    "~/.vscode-insiders/extensions",
    "~/.vscode-oss/extensions",
    "~/.vscodium/extensions",
)


class VSCodeCollector(Collector):
    ecosystem = Ecosystem.VSCODE

    def collect(self) -> list[InstalledPackage]:
        results: list[InstalledPackage] = []
        for d in EXT_DIRS:
            base = Path(os.path.expanduser(d))
            if not base.exists():
                continue
            for ext_dir in base.iterdir():
                if not ext_dir.is_dir():
                    continue
                manifest = ext_dir / "package.json"
                if not manifest.exists():
                    continue
                try:
                    data = json.loads(manifest.read_text(encoding="utf-8", errors="replace"))
                except json.JSONDecodeError:
                    continue
                publisher = data.get("publisher")
                name = data.get("name") or ext_dir.name
                full_name = f"{publisher}.{name}" if publisher else name
                results.append(
                    InstalledPackage(
                        ecosystem=Ecosystem.VSCODE,
                        name=full_name,
                        version=data.get("version"),
                        publisher=publisher,
                        homepage=data.get("homepage"),
                        repo_url=_repo_url(data.get("repository")),
                        location=ext_dir,
                        extras={
                            "host": base.parent.name.lstrip("."),
                            "manifest": str(manifest),
                            "engines": data.get("engines"),
                            "main": data.get("main"),
                        },
                    )
                )
        return results


def _repo_url(repo) -> str | None:
    if isinstance(repo, str):
        return repo
    if isinstance(repo, dict):
        return repo.get("url")
    return None
