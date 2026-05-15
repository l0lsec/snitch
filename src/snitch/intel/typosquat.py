"""Flag installed packages whose names are 1 edit away from a popular package."""

from __future__ import annotations

import logging
from collections.abc import Sequence

from snitch.config import Config
from snitch.core.cache import Cache
from snitch.core.findings import Ecosystem, Evidence, Finding, InstalledPackage, Severity
from snitch.core.orchestrator import IntelSource

from ..heuristics.common import levenshtein

log = logging.getLogger("snitch.intel.typosquat")


# Curated subset of popular packages. Kept short so it ships with the tool;
# `snitch update` can refresh from registry top-charts later.
POPULAR_NPM = {
    "react", "lodash", "express", "axios", "chalk", "commander", "dotenv",
    "moment", "uuid", "yargs", "debug", "next", "vite", "webpack", "typescript",
    "eslint", "prettier", "jest", "mocha", "ws", "request", "cross-env",
    "minimist", "tslib", "rxjs", "redux", "vue", "svelte",
}
POPULAR_PYPI = {
    "requests", "numpy", "pandas", "flask", "django", "fastapi", "pytest",
    "sqlalchemy", "pyyaml", "boto3", "scipy", "matplotlib", "click", "rich",
    "httpx", "pydantic", "typer", "tqdm", "pillow", "cryptography", "tensorflow",
    "torch", "scikit-learn", "openai", "anthropic", "langchain",
}

POPULAR_BY_ECOSYSTEM = {
    Ecosystem.NPM: POPULAR_NPM,
    Ecosystem.PYPI: POPULAR_PYPI,
}


class TyposquatIntel(IntelSource):
    name = "typosquat"

    def __init__(self, config: Config, cache: Cache):
        self.config = config
        self.cache = cache

    def lookup(self, packages: Sequence[InstalledPackage]) -> list[Finding]:
        out: list[Finding] = []
        for pkg in packages:
            popular = POPULAR_BY_ECOSYSTEM.get(pkg.ecosystem)
            if not popular:
                continue
            name = pkg.name.lower().lstrip("@")
            if name in popular:
                continue
            for candidate in popular:
                if abs(len(name) - len(candidate)) > 2:
                    continue
                d = levenshtein(name, candidate)
                if 0 < d <= 1:
                    out.append(self._finding(pkg, candidate, d))
                    break
        return out

    def _finding(
        self, pkg: InstalledPackage, target: str, distance: int
    ) -> Finding:
        return Finding(
            package=pkg,
            rule_id="typosquat.distance",
            title=f"Possible typosquat of '{target}'",
            severity=Severity.MEDIUM,
            description=(
                f"Package name `{pkg.name}` is only {distance} edit away from the "
                f"popular package `{target}`. Confirm you intended to install this one."
            ),
            evidence=[
                Evidence(
                    kind="rule",
                    summary=f"levenshtein('{pkg.name}', '{target}') = {distance}",
                    source="snitch typosquat dictionary",
                )
            ],
        )
