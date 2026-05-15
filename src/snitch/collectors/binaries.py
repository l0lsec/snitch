"""Walk $PATH and inventory standalone binaries."""

from __future__ import annotations

import hashlib
import logging
import os
import platform
from pathlib import Path

from snitch.core.findings import Ecosystem, InstalledPackage
from snitch.core.orchestrator import Collector

from .base import has_command, run_command

log = logging.getLogger("snitch.collectors.binaries")

# Skip well-known "owned" prefixes — those are surfaced by other collectors.
SKIP_PREFIXES = (
    "/usr/bin",
    "/bin",
    "/sbin",
    "/usr/sbin",
    "/opt/homebrew/Cellar",  # brew internals; the symlinks live elsewhere
    "/usr/local/Cellar",
)

# We hash files smaller than this fully; bigger ones are still hashed but we
# skip if they're huge to keep scan times bounded.
MAX_HASH_BYTES = 200 * 1024 * 1024


class BinariesCollector(Collector):
    ecosystem = Ecosystem.BINARY

    def collect(self) -> list[InstalledPackage]:
        path = os.environ.get("PATH", "")
        out: list[InstalledPackage] = []
        seen: set[Path] = set()
        for entry in path.split(os.pathsep):
            if not entry:
                continue
            base = Path(entry)
            if not base.is_dir():
                continue
            try:
                resolved = base.resolve()
            except Exception:
                continue
            if any(str(resolved).startswith(p) for p in SKIP_PREFIXES):
                continue
            for binary in self._walk(base):
                try:
                    real = binary.resolve()
                except Exception:
                    real = binary
                if real in seen:
                    continue
                seen.add(real)
                out.append(self._record(binary, real))
        return out

    @staticmethod
    def _walk(base: Path):
        try:
            for entry in base.iterdir():
                if entry.is_file() and os.access(entry, os.X_OK):
                    yield entry
        except (PermissionError, FileNotFoundError):
            return

    def _record(self, link: Path, real: Path) -> InstalledPackage:
        sha = _sha256(real)
        signature = _codesign(real) if platform.system() == "Darwin" else None
        return InstalledPackage(
            ecosystem=Ecosystem.BINARY,
            name=link.name,
            location=link,
            extras={
                "real_path": str(real),
                "sha256": sha,
                "size": _safe_size(real),
                "codesign": signature,
            },
        )


def _sha256(path: Path) -> str | None:
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > MAX_HASH_BYTES:
        return None
    h = hashlib.sha256()
    try:
        with path.open("rb") as fp:
            for chunk in iter(lambda: fp.read(1 << 16), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def _safe_size(path: Path) -> int | None:
    try:
        return path.stat().st_size
    except OSError:
        return None


def _codesign(path: Path) -> str | None:
    if not has_command("codesign"):
        return None
    _rc, out, err = run_command(["codesign", "-dv", "--verbose=2", str(path)], timeout=10)
    blob = (err or "") + "\n" + (out or "")
    blob = blob.strip()
    if not blob:
        return None
    return blob[:600]
