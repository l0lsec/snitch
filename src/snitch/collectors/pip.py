"""Discover Python packages installed via pip / pipx / system / venvs."""

from __future__ import annotations

import json
import logging
import os
import sys
import sysconfig
from importlib.metadata import Distribution, distributions
from pathlib import Path

from snitch.core.findings import Ecosystem, InstalledPackage
from snitch.core.orchestrator import Collector

from .base import has_command, run_command

log = logging.getLogger("snitch.collectors.pip")

# Common venv locations on macOS / Linux
VENV_GLOBS = (
    "~/.virtualenvs/*",
    "~/.venvs/*",
    "~/.cache/pypoetry/virtualenvs/*",
    "~/Library/Caches/pypoetry/virtualenvs/*",
)

# Per-user "site-packages" trees that aren't venvs. Each entry already points
# at a directory whose subpaths look like ``pythonX.Y/site-packages`` (macOS
# user-site) or ``site-packages`` directly (Linux user-site, Homebrew, etc.).
# These catch packages installed via ``pip install --user`` or shipped with
# the system / Homebrew Python -- which is where vulnerable copies of pip
# itself often live.
USER_SITE_ROOTS = (
    "~/Library/Python",                 # macOS: ~/Library/Python/<X.Y>/lib/python/site-packages
    "~/.local/lib",                     # Linux: ~/.local/lib/pythonX.Y/site-packages
    "/opt/homebrew/lib",                # Apple-silicon Homebrew
    "/usr/local/lib",                   # Intel Homebrew & many Linux distros
    "/opt/homebrew/Frameworks/Python.framework/Versions",  # Homebrew framework
    "/Library/Frameworks/Python.framework/Versions",       # python.org installer
)


class PipCollector(Collector):
    ecosystem = Ecosystem.PYPI

    def collect(self) -> list[InstalledPackage]:
        seen: dict[tuple[str, str | None, str], InstalledPackage] = {}

        for dist in self._scan_current_python():
            self._record(seen, dist, source="current-python")

        for site in self._extra_site_packages():
            for dist in distributions(path=[str(site)]):
                self._record(seen, dist, source=str(site))

        for app, info in self._pipx_apps().items():
            ver = info.get("metadata", {}).get("main_package", {}).get("package_version")
            if not ver:
                ver = info.get("metadata", {}).get("python_version")
            location = info.get("metadata", {}).get("venv")
            seen[(app.lower(), ver, "pipx")] = InstalledPackage(
                ecosystem=Ecosystem.PYPI,
                name=app,
                version=ver,
                location=Path(location) if location else None,
                extras={"installer": "pipx"},
            )

        return list(seen.values())

    # -- helpers -------------------------------------------------------------

    def _record(
        self,
        seen: dict,
        dist: Distribution,
        source: str,
    ) -> None:
        name = dist.metadata["Name"] if dist.metadata else None
        if not name:
            return
        version = dist.version
        dist_info = getattr(dist, "_path", None)
        site: Path | None = None
        if dist_info is not None:
            try:
                site = Path(dist_info).parent
            except Exception:
                site = None
        roots = _resolve_roots(dist, site) if site is not None else []
        primary = roots[0] if roots else (site if site else None)
        key = (name.lower(), version, source)
        if key in seen:
            return
        homepage = dist.metadata.get("Home-page") if dist.metadata else None
        extras: dict = {"source": source}
        if roots:
            extras["roots"] = [str(r) for r in roots]
        if site is not None:
            extras["site_packages"] = str(site)
        if dist_info is not None:
            extras["dist_info"] = str(dist_info)
        seen[key] = InstalledPackage(
            ecosystem=Ecosystem.PYPI,
            name=name,
            version=version,
            location=primary,
            homepage=homepage,
            extras=extras,
        )

    def _scan_current_python(self) -> list[Distribution]:
        return list(distributions())

    def _extra_site_packages(self) -> list[Path]:
        candidates: set[Path] = set()
        # User site
        try:
            user_site = Path(sysconfig.get_paths().get("purelib", ""))
            if user_site.exists():
                candidates.add(user_site)
        except Exception:
            pass
        # Common venv locations
        for pattern in VENV_GLOBS:
            base = Path(os.path.expanduser(pattern.split("*")[0]))
            if not base.exists() or not base.is_dir():
                continue
            for child in base.iterdir():
                if not child.is_dir():
                    continue
                for sp_name in ("lib",):
                    sp = child / sp_name
                    if not sp.exists():
                        continue
                    for py in sp.glob("python*/site-packages"):
                        candidates.add(py)
        # Conda envs
        conda_envs = Path(os.path.expanduser("~/miniconda3/envs"))
        if conda_envs.exists():
            for env in conda_envs.iterdir():
                for py in (env / "lib").glob("python*/site-packages"):
                    candidates.add(py)
        # Per-user / system site-packages outside venvs (pip --user, Homebrew,
        # Apple/python.org-bundled Pythons). Each USER_SITE_ROOTS entry can
        # contain ``pythonX.Y/site-packages`` and/or ``X.Y/lib/python*/site-packages``.
        for root in USER_SITE_ROOTS:
            base = Path(os.path.expanduser(root))
            if not base.exists() or not base.is_dir():
                continue
            for sp in base.glob("python*/site-packages"):
                if sp.is_dir():
                    candidates.add(sp)
            for sp in base.glob("*/lib/python*/site-packages"):
                if sp.is_dir():
                    candidates.add(sp)
            for sp in base.glob("*/lib/python/site-packages"):  # macOS user-site quirk
                if sp.is_dir():
                    candidates.add(sp)
        return [c for c in candidates if c.exists()]

    def _pipx_apps(self) -> dict:
        if not has_command("pipx"):
            return {}
        rc, out, _err = run_command(["pipx", "list", "--json"])
        if rc != 0 or not out.strip():
            return {}
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return {}
        return data.get("venvs", {})


def _resolve_roots(dist: Distribution, site: Path) -> list[Path]:
    """Return the actual import roots a distribution installs into `site`.

    Uses `top_level.txt` first (cheap, accurate for most wheels). Falls back to
    walking `RECORD` / `dist.files` and taking unique top-level entries that
    are not metadata directories. Filters out anything that doesn't actually
    exist on disk so analyzers can't escape the package's own files.
    """

    roots: dict[str, Path] = {}

    def _add(candidate: Path) -> None:
        try:
            resolved = candidate.resolve()
        except OSError:
            return
        if not resolved.exists():
            return
        roots.setdefault(str(resolved), resolved)

    top_text = ""
    try:
        top_text = dist.read_text("top_level.txt") or ""
    except Exception:
        top_text = ""

    for raw in top_text.splitlines():
        name = raw.strip()
        if not name or name.startswith(("_", "-")):
            continue
        as_pkg = site / name
        if as_pkg.is_dir() and not as_pkg.name.endswith((".dist-info", ".egg-info")):
            _add(as_pkg)
            continue
        as_module = site / f"{name}.py"
        if as_module.is_file():
            _add(as_module)

    if roots:
        return sorted(roots.values(), key=lambda p: str(p))

    files = getattr(dist, "files", None) or []
    for entry in files:
        parts = Path(str(entry)).parts
        if not parts:
            continue
        head = parts[0]
        if head in (".", "..", ""):
            continue
        if head.endswith((".dist-info", ".egg-info")):
            continue
        if head.startswith(("_", "-")):
            continue
        candidate = site / head
        if candidate.is_dir():
            _add(candidate)
        elif candidate.is_file() and candidate.suffix == ".py":
            _add(candidate)

    return sorted(roots.values(), key=lambda p: str(p))


def _bootstrap_distinfo() -> None:
    """No-op kept for future use; importlib.metadata works without bootstrapping."""
    _ = sys.path
