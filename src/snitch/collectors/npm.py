"""Discover Node packages installed globally via npm / pnpm / yarn / bun."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from snitch.core.findings import Ecosystem, InstalledPackage
from snitch.core.orchestrator import Collector

from .base import has_command, run_command

log = logging.getLogger("snitch.collectors.npm")


class NpmCollector(Collector):
    ecosystem = Ecosystem.NPM

    def collect(self) -> list[InstalledPackage]:
        results: dict[str, InstalledPackage] = {}

        for pkg in self._npm_global():
            results[pkg.key] = pkg
        for pkg in self._scan_node_modules_dirs():
            results.setdefault(pkg.key, pkg)
        for pkg in self._pnpm_global():
            results.setdefault(pkg.key, pkg)

        return list(results.values())

    # -- npm -----------------------------------------------------------------

    def _npm_global(self) -> list[InstalledPackage]:
        if not has_command("npm"):
            return []
        _rc, out, _err = run_command(["npm", "ls", "-g", "--depth=0", "--json"])
        if not out.strip():
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []
        deps = data.get("dependencies") or {}
        prefix = data.get("path")
        results: list[InstalledPackage] = []
        for name, info in deps.items():
            if not isinstance(info, dict):
                continue
            version = info.get("version")
            location = (
                Path(prefix) / "lib" / "node_modules" / name if prefix else None
            )
            results.append(
                InstalledPackage(
                    ecosystem=Ecosystem.NPM,
                    name=name,
                    version=version,
                    location=location,
                    extras={"installer": "npm-global"},
                )
            )
        return results

    # -- node_modules walk ---------------------------------------------------

    def _scan_node_modules_dirs(self) -> list[InstalledPackage]:
        roots: list[Path] = []
        # `npm root -g`
        if has_command("npm"):
            rc, out, _ = run_command(["npm", "root", "-g"])
            if rc == 0 and out.strip():
                roots.append(Path(out.strip()))
        # Common locations
        for cand in (
            "/usr/local/lib/node_modules",
            "/opt/homebrew/lib/node_modules",
            os.path.expanduser("~/.npm-global/lib/node_modules"),
            os.path.expanduser("~/.nvm/versions/node"),  # iterate
        ):
            p = Path(cand)
            if not p.exists():
                continue
            if p.name == "node":
                # nvm: iterate versions
                for ver in p.iterdir():
                    nm = ver / "lib" / "node_modules"
                    if nm.exists():
                        roots.append(nm)
            else:
                roots.append(p)

        out: list[InstalledPackage] = []
        seen_dirs: set[Path] = set()
        for root in roots:
            try:
                root = root.resolve()
            except Exception:
                continue
            if root in seen_dirs:
                continue
            seen_dirs.add(root)
            for entry in self._iter_node_modules(root):
                pkg = self._read_package_json(entry)
                if pkg is not None:
                    out.append(pkg)
        return out

    @staticmethod
    def _iter_node_modules(root: Path):
        if not root.is_dir():
            return
        for entry in root.iterdir():
            if entry.name.startswith("@") and entry.is_dir():
                for scoped in entry.iterdir():
                    if scoped.is_dir():
                        yield scoped
            elif entry.is_dir() and entry.name != ".bin":
                yield entry

    @staticmethod
    def _read_package_json(pkg_dir: Path) -> InstalledPackage | None:
        manifest = pkg_dir / "package.json"
        if not manifest.exists():
            return None
        try:
            data = json.loads(manifest.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            return None
        name = data.get("name")
        if not name:
            return None
        repo = data.get("repository")
        if isinstance(repo, dict):
            repo = repo.get("url")
        return InstalledPackage(
            ecosystem=Ecosystem.NPM,
            name=name,
            version=data.get("version"),
            location=pkg_dir,
            homepage=data.get("homepage"),
            repo_url=repo if isinstance(repo, str) else None,
            extras={
                "scripts": data.get("scripts") or {},
                "bin": list((data.get("bin") or {}).keys())
                if isinstance(data.get("bin"), dict)
                else (data.get("bin") if isinstance(data.get("bin"), str) else []),
                "manifest": str(manifest),
            },
        )

    # -- pnpm ---------------------------------------------------------------

    def _pnpm_global(self) -> list[InstalledPackage]:
        if not has_command("pnpm"):
            return []
        rc, out, _ = run_command(["pnpm", "ls", "-g", "--depth=0", "--json"])
        if rc != 0 or not out.strip():
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []
        if isinstance(data, list):
            data = data[0] if data else {}
        deps = data.get("dependencies") or {}
        results: list[InstalledPackage] = []
        for name, info in deps.items():
            if not isinstance(info, dict):
                continue
            results.append(
                InstalledPackage(
                    ecosystem=Ecosystem.NPM,
                    name=name,
                    version=info.get("version"),
                    location=Path(info["path"]) if info.get("path") else None,
                    extras={"installer": "pnpm-global"},
                )
            )
        return results
