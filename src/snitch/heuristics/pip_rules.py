"""Heuristic rules for Python packages."""

from __future__ import annotations

import logging
import re
from importlib.metadata import distribution
from pathlib import Path

from snitch.core.findings import Ecosystem, Evidence, Finding, InstalledPackage, Severity
from snitch.core.orchestrator import Analyzer

from .common import make_finding

log = logging.getLogger("snitch.heuristics.pip")


SETUP_SUSPICIOUS = re.compile(
    r"(?:exec|eval|compile|__import__|getattr)\s*\(",
    re.IGNORECASE,
)
ENCODED_PAYLOAD = re.compile(
    r"(base64\.b64decode|codecs\.decode|marshal\.loads|zlib\.decompress)\s*\(",
)
SHELL_TOKENS = (
    "curl ",
    "wget ",
    "| sh",
    "|bash",
    "/dev/tcp/",
    "powershell",
)


class PipHeuristicAnalyzer(Analyzer):
    name = "pip-heuristics"

    def analyze(self, package: InstalledPackage) -> list[Finding]:
        if package.ecosystem != Ecosystem.PYPI:
            return []
        out: list[Finding] = []
        out.extend(self._check_setup_py(package))
        out.extend(self._check_long_description(package))
        return out

    def _check_setup_py(self, pkg: InstalledPackage) -> list[Finding]:
        if not pkg.location:
            return []
        # site-packages stores .dist-info at <location>/<name>-<ver>.dist-info but
        # setup.py only exists for source installs. We try a few candidates.
        candidates: list[Path] = []
        if pkg.location:
            candidates.append(pkg.location)
            candidates.append(pkg.location.parent)
        for base in candidates:
            setup = base / "setup.py" if base else None
            if setup and setup.exists():
                return self._scan_setup(pkg, setup)
        return []

    def _scan_setup(self, pkg: InstalledPackage, setup: Path) -> list[Finding]:
        try:
            text = setup.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        evidence: list[Evidence] = []
        if SETUP_SUSPICIOUS.search(text):
            evidence.append(
                Evidence(
                    kind="rule",
                    summary="setup.py uses exec/eval/__import__/getattr",
                    location=str(setup),
                )
            )
        if ENCODED_PAYLOAD.search(text):
            evidence.append(
                Evidence(
                    kind="rule",
                    summary="setup.py decodes/loads encoded payload at install time",
                    location=str(setup),
                )
            )
        for tok in SHELL_TOKENS:
            if tok in text:
                evidence.append(
                    Evidence(
                        kind="rule",
                        summary=f"setup.py contains shell token '{tok.strip()}'",
                        location=str(setup),
                    )
                )
                break
        if not evidence:
            return []
        return [
            make_finding(
                pkg,
                rule_id="pip.setup-suspicious",
                title="setup.py performs suspicious operations",
                description=(
                    "Code in setup.py runs at install time. Patterns matching exec, "
                    "encoded payloads, or shell command execution warrant review."
                ),
                severity=Severity.HIGH,
                evidence=evidence,
            )
        ]

    def _check_long_description(self, pkg: InstalledPackage) -> list[Finding]:
        try:
            dist = distribution(pkg.name)
        except Exception:
            return []
        meta = dist.metadata
        if not meta:
            return []
        body = meta.get("Description") or ""
        if not body or len(body) < 200:
            return []
        # Look for an unreasonably-large base64 blob hidden in the description.
        if re.search(r"[A-Za-z0-9+/=]{500,}", body):
            return [
                make_finding(
                    pkg,
                    rule_id="pip.payload-in-description",
                    title="Long base64-like blob in package description",
                    description=(
                        "The PyPI description contains a long base64-encoded "
                        "string. Some malicious packages hide payloads here."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=[
                        Evidence(
                            kind="rule",
                            summary=f"description length: {len(body)}",
                            location="METADATA#Description",
                        )
                    ],
                )
            ]
        return []
