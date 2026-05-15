from pathlib import Path

from snitch.collectors.npm import NpmCollector


def test_read_package_json_extracts_metadata(npm_pkg_dir: Path) -> None:
    pkg = NpmCollector._read_package_json(npm_pkg_dir)
    assert pkg is not None
    assert pkg.name == "evil"
    assert pkg.version == "1.0.0"
    assert "postinstall" in pkg.extras["scripts"]


def test_iter_node_modules_handles_scopes(tmp_path: Path) -> None:
    root = tmp_path / "node_modules"
    (root / "@scope" / "pkg").mkdir(parents=True)
    (root / "@scope" / "pkg" / "package.json").write_text('{"name":"@scope/pkg","version":"1"}')
    (root / "plain").mkdir()
    (root / "plain" / "package.json").write_text('{"name":"plain","version":"1"}')
    found = list(NpmCollector._iter_node_modules(root))
    assert any(p.name == "pkg" for p in found)
    assert any(p.name == "plain" for p in found)
