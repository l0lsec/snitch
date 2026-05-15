"""Cross-reference packages against the OSV.dev database.

OSV is the spine of snitch's intelligence layer: a single API surface that
covers GHSA, PyPA advisories, npm advisories, Go vuln DB, RubyGems, crates.io,
and the OpenSSF malicious-packages feed. We use the batched query endpoint
(`/v1/querybatch`) to keep round trips bounded.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence

import httpx

from snitch.config import Config
from snitch.core.cache import Cache
from snitch.core.findings import Ecosystem, Evidence, Finding, InstalledPackage, Severity
from snitch.core.orchestrator import IntelSource

log = logging.getLogger("snitch.intel.osv")

# OSV ecosystem identifiers — see https://ossf.github.io/osv-schema/#affectedpackage-field
ECOSYSTEM_TO_OSV = {
    Ecosystem.NPM: "npm",
    Ecosystem.PYPI: "PyPI",
    Ecosystem.GO: "Go",
    Ecosystem.HOMEBREW: None,  # not in OSV
    Ecosystem.VSCODE: None,
    Ecosystem.BINARY: None,
    Ecosystem.GIT: None,
}

BATCH_SIZE = 1000  # OSV limit


class OSVIntel(IntelSource):
    name = "osv"

    def __init__(
        self,
        config: Config,
        cache: Cache,
        client: httpx.Client | None = None,
    ):
        self.config = config
        self.cache = cache
        self._owns_client = client is None
        self.client = client or httpx.Client(
            base_url=config.osv_endpoint,
            headers={"User-Agent": config.user_agent},
            timeout=30.0,
        )

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    # -------------------------------------------------------------------------

    def lookup(self, packages: Sequence[InstalledPackage]) -> list[Finding]:
        eligible = [
            p for p in packages
            if ECOSYSTEM_TO_OSV.get(p.ecosystem) is not None and p.name and p.version
        ]
        if not eligible:
            return []

        findings: list[Finding] = []
        for batch in _chunks(eligible, BATCH_SIZE):
            try:
                results = self._querybatch(batch)
            except httpx.HTTPError as exc:
                log.warning("OSV querybatch failed: %s", exc)
                continue
            for pkg, vulns in zip(batch, results, strict=False):
                for vuln_ref in vulns:
                    detail = self._fetch_vuln(vuln_ref["id"])
                    if detail is None:
                        continue
                    findings.append(self._to_finding(pkg, detail))
                    self._cache_advisory(pkg, detail)
        return findings

    # -------------------------------------------------------------------------

    def _querybatch(self, packages: Sequence[InstalledPackage]) -> list[list[dict]]:
        body = {
            "queries": [
                {
                    "package": {
                        "name": p.name,
                        "ecosystem": ECOSYSTEM_TO_OSV[p.ecosystem],
                    },
                    "version": p.version,
                }
                for p in packages
            ]
        }
        resp = self.client.post("/v1/querybatch", json=body)
        resp.raise_for_status()
        results = resp.json().get("results", [])
        return [(r or {}).get("vulns", []) or [] for r in results]

    def _fetch_vuln(self, vuln_id: str) -> dict | None:
        cached = self.cache.get_query(f"osv:vuln:{vuln_id}", self.config.advisory_ttl_seconds)
        if cached is not None:
            return cached
        try:
            resp = self.client.get(f"/v1/vulns/{vuln_id}")
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError as exc:
            log.debug("OSV vuln %s fetch failed: %s", vuln_id, exc)
            return None
        self.cache.put_query(f"osv:vuln:{vuln_id}", data)
        return data

    def _cache_advisory(self, pkg: InstalledPackage, vuln: dict) -> None:
        try:
            self.cache.upsert_advisory(
                advisory_id=vuln.get("id", ""),
                ecosystem=pkg.ecosystem,
                name=pkg.name,
                summary=vuln.get("summary"),
                severity=_extract_severity(vuln),
                affected=vuln.get("affected"),
                references=vuln.get("references"),
                raw=vuln,
            )
        except Exception as exc:  # pragma: no cover - best-effort cache write
            log.debug("cache write failed: %s", exc)

    def _to_finding(self, pkg: InstalledPackage, vuln: dict) -> Finding:
        vid = vuln.get("id", "OSV-?")
        summary = vuln.get("summary") or vuln.get("details", "")[:120] or vid
        severity = _severity_from_vuln(vuln)
        is_malicious = _is_malicious(vuln)
        evidence_kind = "malicious-packages" if is_malicious else "advisory"
        url = f"https://osv.dev/vulnerability/{vid}"
        ev = Evidence(
            kind=evidence_kind,
            summary=summary,
            detail=vuln.get("details"),
            source="osv.dev",
            url=url,
        )
        references = []
        for ref in vuln.get("references") or []:
            if isinstance(ref, dict) and ref.get("url"):
                references.append(ref["url"])
        title = "Known malicious package" if is_malicious else "Known vulnerability"
        rule_id = "osv.malicious" if is_malicious else "osv.advisory"
        if is_malicious:
            severity = Severity.CRITICAL
        return Finding(
            package=pkg,
            rule_id=rule_id,
            title=f"{title}: {vid}",
            severity=severity,
            description=summary,
            evidence=[ev],
            references=references[:10],
        )


def _chunks(seq: Sequence, n: int) -> Iterable[Sequence]:
    for i in range(0, len(seq), n):
        yield seq[i : i + n]


def _extract_severity(vuln: dict) -> str | None:
    severities = vuln.get("severity") or []
    if severities and isinstance(severities, list):
        first = severities[0]
        if isinstance(first, dict):
            return first.get("score") or first.get("type")
    db_specific = vuln.get("database_specific") or {}
    if isinstance(db_specific, dict):
        return db_specific.get("severity")
    return None


def _severity_from_vuln(vuln: dict) -> Severity:
    raw = _extract_severity(vuln)
    if not raw:
        return Severity.MEDIUM
    raw_l = str(raw).lower()
    if "critical" in raw_l:
        return Severity.CRITICAL
    if "high" in raw_l:
        return Severity.HIGH
    if "moderate" in raw_l or "medium" in raw_l:
        return Severity.MEDIUM
    if "low" in raw_l:
        return Severity.LOW
    # CVSS vector starting with score range
    if raw_l.startswith("cvss:"):
        return Severity.MEDIUM
    return Severity.MEDIUM


def _is_malicious(vuln: dict) -> bool:
    vid = (vuln.get("id") or "").upper()
    if vid.startswith("MAL-"):
        return True
    db = vuln.get("database_specific") or {}
    if isinstance(db, dict) and db.get("malicious") is True:
        return True
    summary = (vuln.get("summary") or "").lower()
    return "malicious" in summary and "package" in summary


def vulns_for_package(
    intel: OSVIntel, pkg: InstalledPackage
) -> list[Finding]:
    """Convenience for `snitch inspect`."""
    return intel.lookup([pkg])
