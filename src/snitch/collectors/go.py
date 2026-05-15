"""Discover Go-installed binaries and the modules they were built from."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

from snitch.core.findings import Ecosystem, InstalledPackage
from snitch.core.orchestrator import Collector

from .base import has_command, run_command

log = logging.getLogger("snitch.collectors.go")

PATH_RE = re.compile(r"^\s*path\s+(\S+)", re.MULTILINE)
MOD_RE = re.compile(r"^\s*mod\s+(\S+)\s+(\S+)", re.MULTILINE)


class GoCollector(Collector):
    ecosystem = Ecosystem.GO

    def available(self) -> bool:
        return has_command("go") or self._gobin_dir() is not None

    def collect(self) -> list[InstalledPackage]:
        gobin = self._gobin_dir()
        if not gobin:
            return []

        results: list[InstalledPackage] = []
        for entry in gobin.iterdir():
            if not entry.is_file() or not os.access(entry, os.X_OK):
                continue
            name, version, module = self._extract_module(entry)
            results.append(
                InstalledPackage(
                    ecosystem=Ecosystem.GO,
                    name=module or name or entry.name,
                    version=version,
                    location=entry,
                    extras={"binary": entry.name, "module": module},
                )
            )
        return results

    def _gobin_dir(self) -> Path | None:
        if has_command("go"):
            rc, out, _ = run_command(["go", "env", "GOBIN"])
            if rc == 0 and out.strip():
                p = Path(out.strip())
                if p.exists():
                    return p
            rc, out, _ = run_command(["go", "env", "GOPATH"])
            if rc == 0 and out.strip():
                p = Path(out.strip()) / "bin"
                if p.exists():
                    return p
        # Default fallback
        default = Path(os.path.expanduser("~/go/bin"))
        return default if default.exists() else None

    def _extract_module(self, binary: Path) -> tuple[str, str | None, str | None]:
        if not has_command("go"):
            return binary.name, None, None
        rc, out, _ = run_command(["go", "version", "-m", str(binary)], timeout=15)
        if rc != 0:
            return binary.name, None, None
        path_match = PATH_RE.search(out)
        mod_match = MOD_RE.search(out)
        module = mod_match.group(1) if mod_match else (path_match.group(1) if path_match else None)
        version = mod_match.group(2) if mod_match else None
        return binary.name, version, module
