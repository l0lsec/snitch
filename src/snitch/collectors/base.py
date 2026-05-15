"""Shared helpers for collectors."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Iterable
from pathlib import Path


def has_command(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run_command(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return 1, "", str(exc)


def first_existing(paths: Iterable[Path]) -> Path | None:
    for p in paths:
        if p.exists():
            return p
    return None
