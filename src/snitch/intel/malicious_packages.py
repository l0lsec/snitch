"""Local mirror of github.com/ossf/malicious-packages.

OSV.dev already federates this feed, but snitch keeps a local copy so:
  1. Scans work fully offline.
  2. We can match historical/removed packages still on disk.
  3. Lookup is O(1) sqlite read instead of a network round-trip per package.

The repo is laid out as `osv/<ecosystem>/<package>/<id>.json` with the OSV
schema. We index name + version ranges into the SQLite cache.
"""

from __future__ import annotations

import json
import logging
import shutil
from collections.abc import Sequence
from pathlib import Path

from snitch.config import Config
from snitch.core.cache import Cache
from snitch.core.findings import Ecosystem, Evidence, Finding, InstalledPackage, Severity
from snitch.core.orchestrator import IntelSource

from ..collectors.base import has_command, run_command

log = logging.getLogger("snitch.intel.malicious")

REPO_URL = "https://github.com/ossf/malicious-packages.git"

# Map our ecosystem labels onto the directory names used in the repo.
# The repo's actual layout is `osv/malicious/<ecosystem>/<package>/MAL-*.json`.
ECOSYSTEM_DIRS = {
    Ecosystem.NPM: ["npm"],
    Ecosystem.PYPI: ["pypi"],
    Ecosystem.GO: ["go"],
    Ecosystem.VSCODE: ["vscode"],
}


class MaliciousPackagesIntel(IntelSource):
    name = "malicious-packages"

    def __init__(self, config: Config, cache: Cache):
        self.config = config
        self.cache = cache

    # -------------------------------------------------------------------------
    # mirror update

    def update_mirror(self) -> tuple[bool, str]:
        """Clone or pull the ossf/malicious-packages repo."""
        target = self.config.paths.ossf_mirror
        target.parent.mkdir(parents=True, exist_ok=True)
        if not has_command("git"):
            return False, "git not installed"

        if not target.exists():
            rc, _, err = run_command(
                ["git", "clone", "--depth", "1", REPO_URL, str(target)],
                timeout=300,
            )
            if rc != 0:
                return False, f"clone failed: {err.strip()}"
        else:
            rc, _, err = run_command(
                ["git", "-C", str(target), "pull", "--ff-only", "--depth", "1"],
                timeout=300,
            )
            if rc != 0:
                return False, f"pull failed: {err.strip()}"

        count = self.reindex()
        return True, f"indexed {count} entries"

    def remove_mirror(self) -> None:
        target = self.config.paths.ossf_mirror
        if target.exists():
            shutil.rmtree(target)

    def reindex(self) -> int:
        """Walk the local mirror and (re)populate the SQLite index."""
        target = self.config.paths.ossf_mirror
        if not target.exists():
            return 0
        self.cache.reset_malicious()
        count = 0
        for ecosystem, dirs in ECOSYSTEM_DIRS.items():
            for d in dirs:
                # Current repo layout is `osv/malicious/<ecosystem>/...`. We
                # also accept legacy `osv/<ecosystem>/...` and bare
                # `<ecosystem>/...` for forward/backward compatibility.
                candidates = (
                    target / "osv" / "malicious" / d,
                    target / "osv" / d,
                    target / d,
                )
                for base in candidates:
                    if not base.exists():
                        continue
                    for json_path in base.rglob("*.json"):
                        entry = _load(json_path)
                        if not entry:
                            continue
                        for affected in entry.get("affected") or []:
                            pkg = (affected.get("package") or {}).get("name")
                            if not pkg:
                                continue
                            self.cache.upsert_malicious(
                                advisory_id=entry.get("id", json_path.stem),
                                ecosystem=ecosystem,
                                name=pkg,
                                summary=entry.get("summary") or entry.get("details", "")[:200],
                                published=entry.get("published"),
                                modified=entry.get("modified"),
                                source=str(json_path.relative_to(target)),
                                raw=entry,
                            )
                            count += 1
        return count

    # -------------------------------------------------------------------------
    # lookup

    def lookup(self, packages: Sequence[InstalledPackage]) -> list[Finding]:
        if self.cache.malicious_count() == 0:
            return []
        findings: list[Finding] = []
        for pkg in packages:
            if pkg.ecosystem not in ECOSYSTEM_DIRS:
                continue
            entries = self.cache.malicious_for(pkg.ecosystem, pkg.name)
            for entry in entries:
                raw = entry.get("raw_json")
                vuln = json.loads(raw) if raw else {}
                if not _affected(vuln, pkg.version):
                    continue
                findings.append(self._to_finding(pkg, entry, vuln))
        return findings

    def _to_finding(
        self,
        pkg: InstalledPackage,
        entry: dict,
        vuln: dict,
    ) -> Finding:
        vid = entry.get("id") or vuln.get("id", "MAL-?")
        summary = entry.get("summary") or vuln.get("summary") or "Listed in ossf/malicious-packages"
        return Finding(
            package=pkg,
            rule_id="ossf.malicious",
            title=f"Listed in ossf/malicious-packages: {vid}",
            severity=Severity.CRITICAL,
            description=summary,
            evidence=[
                Evidence(
                    kind="malicious-packages",
                    summary=summary,
                    source="ossf/malicious-packages",
                    location=entry.get("source"),
                    url=f"https://github.com/ossf/malicious-packages/blob/main/{entry.get('source', '')}",
                )
            ],
            references=_refs(vuln),
        )


def _load(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None


def _affected(vuln: dict, version: str | None) -> bool:
    """Best-effort version match. If we can't tell, assume affected."""
    if version is None:
        return True
    for affected in vuln.get("affected") or []:
        versions = affected.get("versions") or []
        if version in versions:
            return True
        # Range checks would require packaging-version comparators; for the
        # malicious-packages feed entries are typically explicit version
        # listings or "all versions", so we err on the side of flagging.
        if not versions:
            return True
    return True


def _refs(vuln: dict) -> list[str]:
    out: list[str] = []
    for ref in vuln.get("references") or []:
        if isinstance(ref, dict) and ref.get("url"):
            out.append(ref["url"])
    return out[:10]
