"""Discover Homebrew formulae & casks."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from snitch.core.findings import Ecosystem, InstalledPackage
from snitch.core.orchestrator import Collector

from .base import has_command, run_command

log = logging.getLogger("snitch.collectors.brew")


class BrewCollector(Collector):
    ecosystem = Ecosystem.HOMEBREW

    def available(self) -> bool:
        return has_command("brew")

    def collect(self) -> list[InstalledPackage]:
        results: list[InstalledPackage] = []
        results.extend(self._info("--formula"))
        results.extend(self._info("--cask"))
        return results

    def _info(self, kind_flag: str) -> list[InstalledPackage]:
        # `brew info --installed --json=v2` returns rich metadata for everything
        # currently installed of the requested kind.
        rc, out, _err = run_command(
            ["brew", "info", "--installed", "--json=v2", kind_flag],
            timeout=60,
        )
        if rc != 0 or not out.strip():
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []

        results: list[InstalledPackage] = []
        for entry in data.get("formulae", []):
            installed = entry.get("installed") or [{}]
            ver = installed[0].get("version") if installed else None
            results.append(
                InstalledPackage(
                    ecosystem=Ecosystem.HOMEBREW,
                    name=entry.get("name", ""),
                    version=ver,
                    homepage=entry.get("homepage"),
                    location=Path(installed[0].get("install_dir"))
                    if installed and installed[0].get("install_dir")
                    else None,
                    extras={"kind": "formula", "tap": entry.get("tap")},
                )
            )
        for entry in data.get("casks", []):
            results.append(
                InstalledPackage(
                    ecosystem=Ecosystem.HOMEBREW,
                    name=entry.get("token") or entry.get("name", [""])[0],
                    version=entry.get("installed"),
                    homepage=entry.get("homepage"),
                    extras={"kind": "cask", "tap": entry.get("tap")},
                )
            )
        return results
