"""Heuristic rules for npm packages."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from snitch.core.findings import Ecosystem, Evidence, Finding, InstalledPackage, Severity
from snitch.core.orchestrator import Analyzer

from .common import make_finding

log = logging.getLogger("snitch.heuristics.npm")

LIFECYCLE_SCRIPTS = {"preinstall", "install", "postinstall", "preuninstall"}

# Strings that almost never appear in legitimate lifecycle scripts.
SUSPICIOUS_SCRIPT_TOKENS = (
    "curl ",
    "wget ",
    "| sh",
    "|sh",
    "| bash",
    "|bash",
    "base64 -d",
    "base64 --decode",
    "eval ",
    "powershell",
    "iwr ",
    "Invoke-Expression",
    "/dev/tcp/",
    "nc ",
    "ncat ",
)


class NpmHeuristicAnalyzer(Analyzer):
    name = "npm-heuristics"

    def analyze(self, package: InstalledPackage) -> list[Finding]:
        if package.ecosystem != Ecosystem.NPM:
            return []
        out: list[Finding] = []
        out.extend(self._check_scripts(package))
        out.extend(self._check_repo_mismatch(package))
        out.extend(self._check_main_binaries(package))
        return out

    def _check_scripts(self, pkg: InstalledPackage) -> list[Finding]:
        scripts = (pkg.extras.get("scripts") or {}) if pkg.extras else {}
        if not scripts:
            return []
        findings: list[Finding] = []
        for hook, body in scripts.items():
            if hook not in LIFECYCLE_SCRIPTS:
                continue
            if not isinstance(body, str):
                continue
            severity = Severity.LOW
            evidence_summary = f"{hook} script: {body[:120]}"
            tokens_found = [tok for tok in SUSPICIOUS_SCRIPT_TOKENS if tok in body]
            if tokens_found:
                severity = Severity.HIGH
                evidence_summary = (
                    f"{hook} script contains suspicious tokens "
                    f"({', '.join(tokens_found)}): {body[:200]}"
                )
            findings.append(
                make_finding(
                    pkg,
                    rule_id="npm.lifecycle-script",
                    title=f"npm {hook} script present",
                    description=(
                        "This package runs a script automatically when installed. "
                        "Inspect it before re-installing or upgrading."
                    ),
                    severity=severity,
                    evidence=[
                        Evidence(
                            kind="rule",
                            summary=evidence_summary,
                            location=f"package.json#scripts.{hook}",
                            detail=body,
                        )
                    ],
                )
            )
        return findings

    def _check_repo_mismatch(self, pkg: InstalledPackage) -> list[Finding]:
        if not pkg.repo_url:
            return []
        # Heuristic: repos hosted on hosts other than the major ones, or shortened URLs.
        suspicious_hosts = ("bit.ly", "tinyurl.com", "rb.gy")
        for h in suspicious_hosts:
            if h in pkg.repo_url:
                return [
                    make_finding(
                        pkg,
                        rule_id="npm.repo-url-shortener",
                        title="Repository URL uses a link shortener",
                        description=(
                            "Legitimate packages publish a stable repository URL. "
                            "A shortener is unusual and warrants review."
                        ),
                        severity=Severity.MEDIUM,
                        evidence=[
                            Evidence(
                                kind="rule",
                                summary=f"repo URL: {pkg.repo_url}",
                                location="package.json#repository.url",
                            )
                        ],
                    )
                ]
        return []

    def _check_main_binaries(self, pkg: InstalledPackage) -> list[Finding]:
        bins = (pkg.extras.get("bin") if pkg.extras else None) or []
        if not bins or not pkg.location:
            return []
        # Flag obfuscated / minified entry points that ship many shell-like
        # patterns. We do a fast string check; the AST analyzer will dig deeper.
        out: list[Finding] = []
        names = [bins] if isinstance(bins, str) else bins
        for n in names:
            target = pkg.location / n
            if not target.exists():
                continue
            try:
                head = target.read_text(encoding="utf-8", errors="ignore")[:8192]
            except OSError:
                continue
            if _looks_obfuscated(head):
                out.append(
                    make_finding(
                        pkg,
                        rule_id="npm.obfuscated-entry",
                        title="Binary entry point looks obfuscated",
                        description=(
                            "The package's executable entry point appears to be "
                            "minified or obfuscated, which is uncommon for CLIs."
                        ),
                        severity=Severity.MEDIUM,
                        evidence=[
                            Evidence(
                                kind="rule",
                                summary="entry point >85% non-whitespace and packed",
                                location=str(target),
                            )
                        ],
                    )
                )
        return out


_PACKED_RE = re.compile(r"[a-zA-Z]{40,}")


def _looks_obfuscated(text: str) -> bool:
    if len(text) < 500:
        return False
    nonspace = sum(1 for c in text if not c.isspace())
    ratio = nonspace / len(text)
    if ratio < 0.85:
        return False
    return bool(_PACKED_RE.search(text))


def manifest_for(pkg: InstalledPackage) -> dict | None:
    if not pkg.location:
        return None
    p = pkg.location / "package.json"
    if not p.exists():
        return None
    try:
        return json.loads(Path(p).read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
