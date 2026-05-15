"""AST-based scanning of Python sources within an installed package.

Scope is intentionally narrow: only files that run at install/import time
get analyzed, because that's where Python supply-chain malware typically
hides its payload (``setup.py``, the package's top-level ``__init__.py``
and ``__main__.py``). Random helper modules buried deep in mature
libraries call ``subprocess.run`` / ``compile`` / ``eval`` for legitimate
reasons all the time and are not interesting on their own.

A single suspicious call in a non-install file is suppressed; we only
emit findings when at least two distinct kinds of suspicious calls
co-occur in the same file (e.g. an encoded loader plus ``exec``), or
when the match lives in ``setup.py`` (which executes at install time).
"""

from __future__ import annotations

import ast
import logging
from collections.abc import Iterable
from pathlib import Path

from snitch.core.findings import Ecosystem, Evidence, Finding, InstalledPackage, Severity
from snitch.core.orchestrator import Analyzer

from ._walk import package_roots

log = logging.getLogger("snitch.analyzers.py")

MAX_BYTES = 600_000
INSTALL_TIME_NAMES = frozenset({"__init__.py", "__main__.py", "conftest.py"})

DANGEROUS_CALLS = {
    ("os", "system"),
    ("os", "popen"),
    ("subprocess", "Popen"),
    ("subprocess", "run"),
    ("subprocess", "call"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
    ("subprocess", "getoutput"),
    ("subprocess", "getstatusoutput"),
    ("pty", "spawn"),
}
ENCODED_LOAD = {
    ("base64", "b64decode"),
    ("base64", "decodebytes"),
    ("codecs", "decode"),
    ("marshal", "loads"),
    ("zlib", "decompress"),
    ("pickle", "loads"),
}


class PyAstAnalyzer(Analyzer):
    name = "py-ast"

    def analyze(self, package: InstalledPackage) -> list[Finding]:
        if package.ecosystem != Ecosystem.PYPI:
            return []
        roots = package_roots(package)
        if not roots:
            return []

        findings: list[Finding] = []
        for path, is_setup in self._iter_install_time_files(roots, package):
            findings.extend(self._scan_file(package, path, is_setup=is_setup))
        return findings

    def _iter_install_time_files(
        self, roots: list[Path], package: InstalledPackage
    ) -> Iterable[tuple[Path, bool]]:
        """Yield ``(path, is_setup)`` for files that run at install/import time.

        - ``setup.py`` is checked at the parent of each root (source-installed
          packages) and at the ``site-packages`` directory recorded by the
          collector (rare but possible for legacy egg layouts).
        - Inside each root, only the top-level ``__init__.py`` / ``__main__.py``
          / ``conftest.py`` files are scanned. Nested ``__init__.py`` files
          across deep subpackages are skipped to keep noise down.
        """
        seen: set[Path] = set()

        candidate_setup_dirs: list[Path] = []
        for r in roots:
            if r.is_file():
                candidate_setup_dirs.append(r.parent)
            else:
                candidate_setup_dirs.append(r.parent)
        site_pkgs = (package.extras or {}).get("site_packages")
        if site_pkgs:
            try:
                candidate_setup_dirs.append(Path(site_pkgs))
            except Exception:
                pass

        for d in candidate_setup_dirs:
            setup = d / "setup.py"
            if setup.exists() and self._size_ok(setup) and setup not in seen:
                seen.add(setup)
                yield setup, True

        for r in roots:
            if r.is_file():
                if r.name in INSTALL_TIME_NAMES and self._size_ok(r) and r not in seen:
                    seen.add(r)
                    yield r, False
                continue
            for name in INSTALL_TIME_NAMES:
                p = r / name
                if p.exists() and self._size_ok(p) and p not in seen:
                    seen.add(p)
                    yield p, False

    @staticmethod
    def _size_ok(p: Path) -> bool:
        try:
            return p.stat().st_size <= MAX_BYTES
        except OSError:
            return False

    def _scan_file(
        self, pkg: InstalledPackage, path: Path, *, is_setup: bool
    ) -> list[Finding]:
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            return []
        visitor = _PyVisitor()
        visitor.visit(tree)
        if not visitor.hits:
            return []

        kinds = {kind for kind, _label, _node in visitor.hits}
        # Outside of install-time scripts, require co-occurrence of two
        # different kinds before reporting; a lone ``compile()`` or
        # ``subprocess.run`` is far too common to flag on its own.
        if not is_setup and len(kinds) < 2:
            return []

        findings: list[Finding] = []
        emitted: set[tuple[str, str]] = set()
        for kind, label, node in visitor.hits:
            key = (kind, label)
            if key in emitted:
                continue
            emitted.add(key)
            sev = (
                Severity.HIGH
                if is_setup
                else (Severity.MEDIUM if kind != "exec" else Severity.LOW)
            )
            rule = f"py.{kind}"
            where = "setup.py" if is_setup else path.name
            findings.append(
                Finding(
                    package=pkg,
                    rule_id=rule,
                    title=f"Suspicious Python call: {label}",
                    severity=sev,
                    description=(
                        "Static analysis spotted a call commonly used in malicious "
                        f"Python packages, in {where}."
                    ),
                    evidence=[
                        Evidence(
                            kind="ast",
                            summary=f"{label} at {path.name}:{node.lineno}",
                            location=f"{path}:{node.lineno}",
                        )
                    ],
                )
            )
        return findings


class _PyVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[tuple[str, str, ast.AST]] = []

    def visit_Call(self, node: ast.Call) -> None:
        label = _call_name(node.func)
        if label in {"exec", "eval", "compile"}:
            self.hits.append(("exec", label, node))
        else:
            parts = label.split(".") if label else []
            if len(parts) == 2 and (parts[0], parts[1]) in DANGEROUS_CALLS:
                self.hits.append(("subprocess", label, node))
            if len(parts) == 2 and (parts[0], parts[1]) in ENCODED_LOAD:
                self.hits.append(("encoded", label, node))
        self.generic_visit(node)


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""
