"""Runtime paths + configuration for snitch.

Default data location is `<project_root>/.snitch/` — i.e. a hidden directory
next to the `pyproject.toml` of the installed snitch package. This keeps the
cache, malicious-packages mirror, and ignore file with the tool itself, so
multiple checkouts can't poison each other. When snitch is installed in a way
that has no discoverable project root (e.g. a vanilla `pipx install snitch`
into site-packages), we fall back to the XDG dirs we used historically.

If app-local is selected but XDG data exists (an upgrade from older snitch
versions), the XDG payload is migrated into the app-local directory on first
run so the user doesn't have to re-clone the 200k-entry mirror.
"""

from __future__ import annotations

import logging
import os
import shutil
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from platformdirs import user_cache_dir, user_config_dir

APP_NAME = "snitch"
APP_DIRNAME = ".snitch"
DB_FILENAME = "snitch.db"
MIRROR_DIRNAME = "malicious-packages"
IGNORE_FILENAME = "ignore.toml"

log = logging.getLogger("snitch.config")


# ---------------------------------------------------------------------------
# project-root discovery
# ---------------------------------------------------------------------------


def _read_pyproject_name(pyproject: Path) -> str | None:
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return None
    project = data.get("project")
    if isinstance(project, dict):
        name = project.get("name")
        if isinstance(name, str):
            return name
    return None


def _find_project_root(start: Path | None = None) -> Path | None:
    """Walk up from `start` looking for a pyproject.toml whose project.name == 'snitch'.

    `start` defaults to the directory containing this module. When snitch is
    installed as a wheel in site-packages there's no pyproject.toml in any
    parent, so we return None and callers fall back to XDG.
    """
    here = (start or Path(__file__)).resolve()
    if here.is_file():
        here = here.parent
    for candidate in (here, *here.parents):
        pyproject = candidate / "pyproject.toml"
        if pyproject.exists() and _read_pyproject_name(pyproject) == APP_NAME:
            return candidate
    return None


def _is_dir_writable(path: Path) -> bool:
    """True if `path` (or its nearest existing ancestor) is writable."""
    p = path
    while not p.exists():
        if p.parent == p:
            return False
        p = p.parent
    return os.access(p, os.W_OK)


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Paths:
    cache_dir: Path
    config_dir: Path
    db_path: Path
    ossf_mirror: Path
    ignore_file: Path
    is_app_local: bool = False
    project_root: Path | None = None

    # ----- constructors -----------------------------------------------------

    @classmethod
    def xdg(cls) -> Paths:
        """The legacy XDG-style locations (Library/Caches on macOS)."""
        cache = Path(user_cache_dir(APP_NAME))
        config = Path(user_config_dir(APP_NAME))
        return cls(
            cache_dir=cache,
            config_dir=config,
            db_path=cache / DB_FILENAME,
            ossf_mirror=cache / MIRROR_DIRNAME,
            ignore_file=config / IGNORE_FILENAME,
            is_app_local=False,
            project_root=None,
        )

    @classmethod
    def app_local(cls, project_root: Path) -> Paths:
        """Paths anchored at `<project_root>/.snitch/`."""
        base = project_root / APP_DIRNAME
        return cls(
            cache_dir=base,
            config_dir=base,
            db_path=base / DB_FILENAME,
            ossf_mirror=base / MIRROR_DIRNAME,
            ignore_file=base / IGNORE_FILENAME,
            is_app_local=True,
            project_root=project_root,
        )

    @classmethod
    def discover(cls) -> Paths:
        """Pick the best paths for the current install.

        Order of preference:
          1. If a snitch project root is discoverable AND writable AND
             app-local data already exists there  -> app-local
          2. If a snitch project root is discoverable AND writable          -> app-local
             (the caller may later migrate XDG data into it)
          3. Otherwise                                                       -> XDG
        """
        root = _find_project_root()
        if root is not None and _is_dir_writable(root):
            return cls.app_local(root)
        return cls.xdg()

    # ----- mutators --------------------------------------------------------

    def ensure(self) -> Paths:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        return self


# ---------------------------------------------------------------------------
# Migration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MigrationResult:
    moved_db: bool = False
    moved_mirror: bool = False
    moved_ignore: bool = False
    fell_back_to_xdg: bool = False
    error: str | None = None

    @property
    def any_moved(self) -> bool:
        return self.moved_db or self.moved_mirror or self.moved_ignore


def migrate_xdg_to_app_local(
    target: Paths,
    source: Paths | None = None,
) -> MigrationResult:
    """Move XDG-cached snitch data into the app-local directory if appropriate.

    No-op unless `target` is app-local AND its db is missing AND XDG data
    exists. Best-effort: on failure we leave the XDG copy in place and the
    caller can decide whether to fall back to XDG.
    """
    if not target.is_app_local:
        return MigrationResult()
    source = source or Paths.xdg()
    if target.db_path.exists():
        return MigrationResult()
    if not any(
        (
            source.db_path.exists(),
            source.ossf_mirror.exists(),
            source.ignore_file.exists(),
        )
    ):
        return MigrationResult()

    try:
        target.cache_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return MigrationResult(error=str(exc), fell_back_to_xdg=True)

    moved_db = _move(source.db_path, target.db_path)
    # WAL/journal siblings if they exist
    for suffix in ("-wal", "-shm", "-journal"):
        _move(
            source.db_path.with_name(source.db_path.name + suffix),
            target.db_path.with_name(target.db_path.name + suffix),
        )
    moved_mirror = _move(source.ossf_mirror, target.ossf_mirror)
    moved_ignore = _move(source.ignore_file, target.ignore_file)

    return MigrationResult(
        moved_db=moved_db,
        moved_mirror=moved_mirror,
        moved_ignore=moved_ignore,
    )


def _move(src: Path, dst: Path) -> bool:
    if not src.exists():
        return False
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        return True
    except OSError as exc:
        log.warning("could not migrate %s -> %s: %s", src, dst, exc)
        # If a cross-device move sneaks past shutil.move's copy fallback, try
        # an explicit copy+remove for files. (shutil.move already does this,
        # but Path.is_dir cases on read-only mounts can fail differently.)
        try:
            if src.is_dir():
                shutil.copytree(src, dst, dirs_exist_ok=True)
                shutil.rmtree(src)
            else:
                shutil.copy2(src, dst)
                src.unlink()
            return True
        except OSError as exc2:
            log.warning("copy-fallback also failed for %s: %s", src, exc2)
            return False


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Config:
    paths: Paths = field(default_factory=Paths.xdg)
    vt_api_key: str | None = None
    osv_endpoint: str = "https://api.osv.dev"
    npm_registry: str = "https://registry.npmjs.org"
    pypi_registry: str = "https://pypi.org"
    advisory_ttl_seconds: int = 60 * 60 * 24  # 24h
    user_agent: str = "snitch/0.1 (+https://github.com/your-handle/snitch)"

    @classmethod
    def from_env(cls) -> Config:
        paths = Paths.discover()
        # Best-effort one-shot migration from XDG. Silent on success; logged
        # on failure so the user sees what happened with --verbose.
        result = migrate_xdg_to_app_local(paths)
        if result.error and not paths.db_path.exists():
            # Couldn't even create the app-local dir — fall back to XDG.
            paths = Paths.xdg()
        paths.ensure()
        return cls(
            paths=paths,
            vt_api_key=os.environ.get("SNITCH_VT_API_KEY"),
        )
