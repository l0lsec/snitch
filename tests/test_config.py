"""Tests for path discovery, app-local preference, and XDG migration."""

from __future__ import annotations

from pathlib import Path

import pytest

from snitch import config as config_mod
from snitch.config import (
    APP_DIRNAME,
    DB_FILENAME,
    IGNORE_FILENAME,
    MIRROR_DIRNAME,
    Paths,
    _find_project_root,
    migrate_xdg_to_app_local,
)


def _make_project(tmp_path: Path, name: str = "snitch") -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nname = "{name}"\nversion = "0.0.0"\n',
        encoding="utf-8",
    )
    (tmp_path / "src" / "snitch").mkdir(parents=True)
    return tmp_path


def test_find_project_root_walks_up(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    nested = project / "src" / "snitch"
    assert _find_project_root(nested / "config.py") == project.resolve()


def test_find_project_root_ignores_other_packages(tmp_path: Path) -> None:
    project = _make_project(tmp_path, name="someoneelse")
    assert _find_project_root(project / "src" / "snitch" / "x.py") is None


def test_find_project_root_returns_none_for_orphan_path(tmp_path: Path) -> None:
    # No pyproject.toml anywhere up the tree.
    deep = tmp_path / "a" / "b" / "c"
    deep.mkdir(parents=True)
    # tmp_path itself has no pyproject.toml; walk stops at filesystem root.
    assert _find_project_root(deep) is None


def test_app_local_paths_layout(tmp_path: Path) -> None:
    project = _make_project(tmp_path)
    paths = Paths.app_local(project)
    base = project / APP_DIRNAME
    assert paths.cache_dir == base
    assert paths.config_dir == base
    assert paths.db_path == base / DB_FILENAME
    assert paths.ossf_mirror == base / MIRROR_DIRNAME
    assert paths.ignore_file == base / IGNORE_FILENAME
    assert paths.is_app_local is True
    assert paths.project_root == project


def test_discover_prefers_app_local_when_project_root_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _make_project(tmp_path)
    fake_module = project / "src" / "snitch" / "config.py"
    fake_module.parent.mkdir(parents=True, exist_ok=True)
    fake_module.write_text("# placeholder\n", encoding="utf-8")
    monkeypatch.setattr(config_mod, "__file__", str(fake_module))
    paths = Paths.discover()
    assert paths.is_app_local is True
    assert paths.project_root == project.resolve()


def test_discover_falls_back_to_xdg_without_project_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    orphan = tmp_path / "site-packages" / "snitch" / "config.py"
    orphan.parent.mkdir(parents=True)
    orphan.write_text("# placeholder\n", encoding="utf-8")
    monkeypatch.setattr(config_mod, "__file__", str(orphan))
    paths = Paths.discover()
    assert paths.is_app_local is False
    assert paths.project_root is None


def test_migrate_moves_db_mirror_and_ignore(tmp_path: Path) -> None:
    project = _make_project(tmp_path / "proj")
    xdg_cache = tmp_path / "xdg-cache"
    xdg_config = tmp_path / "xdg-config"
    xdg_cache.mkdir()
    xdg_config.mkdir()
    src_db = xdg_cache / DB_FILENAME
    src_db.write_text("db", encoding="utf-8")
    (xdg_cache / MIRROR_DIRNAME).mkdir()
    (xdg_cache / MIRROR_DIRNAME / "marker.txt").write_text("hi", encoding="utf-8")
    (xdg_config / IGNORE_FILENAME).write_text("[[ignore]]\n", encoding="utf-8")
    src = Paths(
        cache_dir=xdg_cache,
        config_dir=xdg_config,
        db_path=src_db,
        ossf_mirror=xdg_cache / MIRROR_DIRNAME,
        ignore_file=xdg_config / IGNORE_FILENAME,
        is_app_local=False,
    )
    dst = Paths.app_local(project)

    result = migrate_xdg_to_app_local(dst, src)
    assert result.moved_db
    assert result.moved_mirror
    assert result.moved_ignore
    assert dst.db_path.exists()
    assert (dst.ossf_mirror / "marker.txt").exists()
    assert dst.ignore_file.exists()
    assert not src_db.exists()


def test_migrate_is_noop_when_app_local_db_already_exists(tmp_path: Path) -> None:
    project = _make_project(tmp_path / "proj")
    dst = Paths.app_local(project)
    dst.cache_dir.mkdir(parents=True)
    dst.db_path.write_text("existing", encoding="utf-8")

    xdg_cache = tmp_path / "xdg-cache"
    xdg_cache.mkdir()
    legacy_db = xdg_cache / DB_FILENAME
    legacy_db.write_text("legacy", encoding="utf-8")
    src = Paths(
        cache_dir=xdg_cache,
        config_dir=xdg_cache,
        db_path=legacy_db,
        ossf_mirror=xdg_cache / MIRROR_DIRNAME,
        ignore_file=xdg_cache / IGNORE_FILENAME,
        is_app_local=False,
    )

    result = migrate_xdg_to_app_local(dst, src)
    assert not result.any_moved
    assert legacy_db.read_text() == "legacy"
    assert dst.db_path.read_text() == "existing"


def test_migrate_is_noop_for_xdg_target(tmp_path: Path) -> None:
    src = Paths.xdg()
    result = migrate_xdg_to_app_local(src, src)
    assert not result.any_moved
