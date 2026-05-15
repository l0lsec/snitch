"""Domain model: installed packages, findings, severities, evidence."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum
from pathlib import Path
from typing import Any


class Ecosystem(str):
    """Loose enum so external code can pass plain strings."""

    NPM = "npm"
    PYPI = "PyPI"
    GO = "Go"
    HOMEBREW = "Homebrew"
    VSCODE = "VSCode"
    BINARY = "Binary"
    GIT = "Git"

    @staticmethod
    def all() -> list[str]:
        return [
            Ecosystem.NPM,
            Ecosystem.PYPI,
            Ecosystem.GO,
            Ecosystem.HOMEBREW,
            Ecosystem.VSCODE,
            Ecosystem.BINARY,
            Ecosystem.GIT,
        ]

    @staticmethod
    def normalize(value: str) -> str:
        v = value.strip().lower()
        mapping = {
            "pip": Ecosystem.PYPI,
            "pypi": Ecosystem.PYPI,
            "python": Ecosystem.PYPI,
            "npm": Ecosystem.NPM,
            "node": Ecosystem.NPM,
            "go": Ecosystem.GO,
            "golang": Ecosystem.GO,
            "brew": Ecosystem.HOMEBREW,
            "homebrew": Ecosystem.HOMEBREW,
            "vscode": Ecosystem.VSCODE,
            "cursor": Ecosystem.VSCODE,
            "binary": Ecosystem.BINARY,
            "binaries": Ecosystem.BINARY,
            "github": Ecosystem.GIT,
            "git": Ecosystem.GIT,
        }
        return mapping.get(v, value)


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def from_str(cls, raw: str | None) -> Severity:
        if not raw:
            return cls.MEDIUM
        v = raw.strip().lower()
        for s in cls:
            if s.name.lower() == v:
                return s
        if v in {"warning", "warn"}:
            return cls.MEDIUM
        if v in {"error", "danger"}:
            return cls.HIGH
        return cls.MEDIUM


@dataclass
class InstalledPackage:
    """A single installed unit: a package, extension, repo, or binary."""

    ecosystem: str
    name: str
    version: str | None = None
    location: Path | None = None
    publisher: str | None = None
    homepage: str | None = None
    repo_url: str | None = None
    extras: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        ver = self.version or "*"
        return f"{self.ecosystem}:{self.name}@{ver}"

    @property
    def display(self) -> str:
        if self.version:
            return f"{self.name} {self.version}"
        return self.name


@dataclass
class Evidence:
    """A single supporting fact attached to a finding."""

    kind: str  # "advisory" | "rule" | "ast" | "ioc" | "metadata"
    summary: str
    detail: str | None = None
    source: str | None = None
    url: str | None = None
    location: str | None = None  # file path or "package.json#scripts.postinstall"


@dataclass
class Finding:
    """A single concern about an installed package."""

    package: InstalledPackage
    rule_id: str
    title: str
    severity: Severity
    description: str
    evidence: list[Evidence] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    score: int = 0  # populated by scoring.py

    @property
    def short(self) -> str:
        return f"[{self.severity.label}] {self.package.key} — {self.title} ({self.rule_id})"
