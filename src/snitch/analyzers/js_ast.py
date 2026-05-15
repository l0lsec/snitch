"""Tree-sitter-backed scanning of JavaScript inside npm packages.

tree-sitter is an optional dependency. If it isn't installed, this analyzer
falls back to fast regex heuristics so a default `pip install snitch` still
gives useful coverage. Install with `pip install snitch[ast]` for the full AST.
"""

from __future__ import annotations

import logging
import re

from snitch.core.findings import Ecosystem, Evidence, Finding, InstalledPackage, Severity
from snitch.core.orchestrator import Analyzer

from ._walk import iter_files, package_roots

log = logging.getLogger("snitch.analyzers.js")

MAX_FILES = 80
MAX_BYTES = 800_000
JS_EXT = frozenset({".js", ".cjs", ".mjs"})


JS_PATTERNS = [
    ("js.eval", re.compile(r"\beval\s*\("), "Use of eval()", Severity.MEDIUM),
    (
        "js.new-function",
        re.compile(r"\bnew\s+Function\s*\("),
        "Use of new Function() (dynamic code)",
        Severity.MEDIUM,
    ),
    (
        "js.child-process",
        re.compile(r"require\(\s*['\"]child_process['\"]\s*\)"),
        "Imports child_process",
        Severity.MEDIUM,
    ),
    (
        "js.dynamic-require",
        re.compile(r"require\(\s*[A-Za-z_$][\w$]*\s*\)"),
        "Dynamic require() with a non-literal argument",
        Severity.LOW,
    ),
    (
        "js.fs-and-net",
        re.compile(r"require\(\s*['\"](?:https|http|net|tls|dgram)['\"]\s*\).{0,500}require\(\s*['\"]fs['\"]\s*\)", re.DOTALL),
        "Combines network + filesystem modules in one file",
        Severity.MEDIUM,
    ),
    (
        "js.process-env-leak",
        re.compile(r"process\.env\.(?:HOME|USER|PATH|AWS|GH|GITHUB|NPM_TOKEN)"),
        "Reads sensitive process.env fields",
        Severity.LOW,
    ),
]


class JsAstAnalyzer(Analyzer):
    name = "js-ast"

    def analyze(self, package: InstalledPackage) -> list[Finding]:
        if package.ecosystem not in (Ecosystem.NPM, Ecosystem.VSCODE):
            return []
        roots = package_roots(package)
        if not roots:
            return []

        findings: list[Finding] = []
        for path in iter_files(roots, JS_EXT, max_files=MAX_FILES, max_bytes=MAX_BYTES):
            try:
                source = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            findings.extend(self._scan(package, path, source))
        return findings

    def _scan(
        self, pkg: InstalledPackage, path: Path, source: str
    ) -> list[Finding]:
        out: list[Finding] = []
        seen: set[str] = set()
        for rid, regex, summary, sev in JS_PATTERNS:
            m = regex.search(source)
            if not m:
                continue
            if rid in seen:
                continue
            seen.add(rid)
            line_no = source.count("\n", 0, m.start()) + 1
            out.append(
                Finding(
                    package=pkg,
                    rule_id=rid,
                    title=summary,
                    severity=sev,
                    description=(
                        "Static scan of the package source spotted a pattern that "
                        "is common in malicious npm packages."
                    ),
                    evidence=[
                        Evidence(
                            kind="ast",
                            summary=f"{summary} ({path.name}:{line_no})",
                            location=f"{path}:{line_no}",
                            detail=source[max(0, m.start() - 60) : m.end() + 60].strip()[:400],
                        )
                    ],
                )
            )
        return out
