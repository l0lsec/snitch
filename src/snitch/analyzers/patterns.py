"""Cheap regex/IOC scanning for arbitrary text content in installed packages.

Runs across JS / TS / Python / shell files and looks for known-bad strings:
shell installers piped from the network, hex-encoded payloads, suspicious
DNS exfiltration domains, and references to known dropper paths.
"""

from __future__ import annotations

import logging
import re

from snitch.core.findings import Ecosystem, Evidence, Finding, InstalledPackage, Severity
from snitch.core.orchestrator import Analyzer

from ._walk import iter_files, package_roots

log = logging.getLogger("snitch.analyzers.patterns")

ALLOWED_EXT = frozenset({".js", ".cjs", ".mjs", ".ts", ".py", ".sh", ".bash", ".zsh", ".rb"})
MAX_FILE_BYTES = 1_000_000  # 1 MB
MAX_FILES_PER_PACKAGE = 200

PATTERNS: list[tuple[str, str, str, Severity]] = [
    (
        "ioc.curl-pipe-shell",
        r"curl[^\n]{0,100}?\|\s*(?:sh|bash)",
        "curl … | sh remote installer",
        Severity.HIGH,
    ),
    (
        "ioc.wget-pipe-shell",
        r"wget[^\n]{0,100}?\|\s*(?:sh|bash)",
        "wget … | sh remote installer",
        Severity.HIGH,
    ),
    (
        "ioc.devtcp",
        r"/dev/tcp/[^\s]+",
        "/dev/tcp reverse-shell pattern",
        Severity.HIGH,
    ),
    (
        "ioc.base64-exec",
        r"base64\s*(?:--decode|-d)[^\n]{0,80}?\|\s*(?:sh|bash|python)",
        "base64 decode piped to interpreter",
        Severity.HIGH,
    ),
    (
        "ioc.python-exec-encoded",
        r"exec\s*\(\s*(?:base64\.b64decode|bytes\.fromhex|codecs\.decode)",
        "Python exec of decoded payload",
        Severity.HIGH,
    ),
    (
        "ioc.eval-fromcharcode",
        r"eval\s*\(\s*(?:String|window|globalThis)\.fromCharCode",
        "JS eval of String.fromCharCode payload",
        Severity.HIGH,
    ),
    (
        "ioc.discord-webhook",
        r"https://(?:discord(?:app)?|canary\.discord)\.com/api/webhooks/",
        "Discord webhook URL (often used as exfil sink)",
        Severity.MEDIUM,
    ),
    (
        "ioc.telegram-bot",
        r"https://api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_-]+/",
        "Telegram bot API URL with embedded token",
        Severity.MEDIUM,
    ),
    (
        "ioc.aws-key",
        r"AKIA[0-9A-Z]{16}",
        "AWS access key ID literal",
        Severity.MEDIUM,
    ),
]


def _relative_to_any(path, roots):
    for r in roots:
        try:
            return path.relative_to(r)
        except ValueError:
            continue
    return path


class IocPatternAnalyzer(Analyzer):
    name = "ioc-patterns"

    def __init__(self) -> None:
        self._compiled = [
            (rid, re.compile(pat), summary, sev)
            for rid, pat, summary, sev in PATTERNS
        ]

    def analyze(self, package: InstalledPackage) -> list[Finding]:
        if package.ecosystem in (Ecosystem.BINARY, Ecosystem.HOMEBREW):
            # No source tree to read; heuristics for those live elsewhere.
            return []
        roots = package_roots(package)
        if not roots:
            return []

        seen: dict[str, Finding] = {}
        for path in iter_files(
            roots,
            ALLOWED_EXT,
            max_files=MAX_FILES_PER_PACKAGE,
            max_bytes=MAX_FILE_BYTES,
        ):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = _relative_to_any(path, roots)
            for rid, regex, summary, sev in self._compiled:
                m = regex.search(text)
                if not m:
                    continue
                snippet = text[max(0, m.start() - 60) : m.end() + 60]
                key = f"{rid}:{path}"
                seen.setdefault(
                    key,
                    Finding(
                        package=package,
                        rule_id=rid,
                        title=summary,
                        severity=sev,
                        description=(
                            f"Indicator-of-compromise pattern matched in `{rel}`."
                        ),
                        evidence=[
                            Evidence(
                                kind="ioc",
                                summary=summary,
                                location=str(path),
                                detail=snippet.strip()[:400],
                            )
                        ],
                    ),
                )
        return list(seen.values())
