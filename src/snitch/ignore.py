"""Allow-listing for known-good findings.

The ignore file is a simple TOML document of the form::

    [[ignore]]
    rule_id = "npm.lifecycle-script"
    package = "npm:esbuild"           # ecosystem:name (no version → all versions)
    reason  = "official build hook"

Findings matching any rule are filtered out before scoring/reporting.
"""

from __future__ import annotations

import logging
import tomllib  # type: ignore[no-redef]
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .core.findings import Finding

log = logging.getLogger("snitch.ignore")


@dataclass(frozen=True)
class IgnoreRule:
    rule_id: str | None = None
    package: str | None = None  # "ecosystem:name" or "ecosystem:name@version"
    reason: str | None = None

    def matches(self, finding: Finding) -> bool:
        if self.rule_id and finding.rule_id != self.rule_id:
            return False
        if self.package:
            target = self.package.lower()
            key = finding.package.key.lower()
            if "@" in target:
                if target != key:
                    return False
            else:
                # match ecosystem:name regardless of version
                base = key.split("@", 1)[0]
                if target != base:
                    return False
        return True


class IgnoreList:
    def __init__(self, path: Path):
        self.path = path
        self.rules: list[IgnoreRule] = []
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            self.rules = []
            return
        try:
            data = tomllib.loads(self.path.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning("could not parse %s: %s", self.path, exc)
            self.rules = []
            return
        rules = []
        for entry in data.get("ignore", []) or []:
            rules.append(
                IgnoreRule(
                    rule_id=entry.get("rule_id"),
                    package=entry.get("package"),
                    reason=entry.get("reason"),
                )
            )
        self.rules = rules

    def filter(self, findings: Iterable[Finding]) -> list[Finding]:
        if not self.rules:
            return list(findings)
        kept: list[Finding] = []
        for f in findings:
            if any(r.matches(f) for r in self.rules):
                continue
            kept.append(f)
        return kept

    def add(self, rule_id: str | None, package: str | None, reason: str | None) -> None:
        new = IgnoreRule(rule_id=rule_id, package=package, reason=reason)
        self.rules.append(new)
        self.save()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lines: list[str] = []
        for r in self.rules:
            lines.append("[[ignore]]")
            if r.rule_id:
                lines.append(f'rule_id = "{r.rule_id}"')
            if r.package:
                lines.append(f'package = "{r.package}"')
            if r.reason:
                escaped = r.reason.replace('"', '\\"')
                lines.append(f'reason  = "{escaped}"')
            lines.append("")
        self.path.write_text("\n".join(lines), encoding="utf-8")
