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
    """Best-effort summary string for cache rows; not used for bucketing."""
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
    """Resolve a Severity bucket that matches what OSV/GHSA actually reports.

    Order of preference:
      1. ``database_specific.severity`` keyword (LOW/MODERATE/HIGH/CRITICAL).
         GHSA-sourced entries populate this faithfully, so we trust it first.
      2. The maximum severity derivable from any entry in ``severity[]``:
         label/number scores parsed directly, CVSS v3.x vectors scored via
         the v3.1 base formula, CVSS v4.0 vectors bucketed from their
         ``VC/VI/VA/SC/SI/SA`` macro indicators.
      3. ``MEDIUM`` only when nothing parseable exists.
    """
    db_specific = vuln.get("database_specific") or {}
    if isinstance(db_specific, dict):
        sev = _label_to_severity(db_specific.get("severity"))
        if sev is not None:
            return sev

    best: Severity | None = None
    for entry in vuln.get("severity") or []:
        if not isinstance(entry, dict):
            continue
        score_raw = entry.get("score")
        sev = _score_to_severity(score_raw)
        if sev is None:
            sev = _label_to_severity(score_raw)
        if sev is None:
            continue
        if best is None or sev > best:
            best = sev

    return best if best is not None else Severity.MEDIUM


def _label_to_severity(raw: object) -> Severity | None:
    if not isinstance(raw, str) or not raw:
        return None
    s = raw.strip().lower()
    if "critical" in s:
        return Severity.CRITICAL
    if "high" in s:
        return Severity.HIGH
    if "moderate" in s or "medium" in s:
        return Severity.MEDIUM
    if "low" in s:
        return Severity.LOW
    if s in {"none", "info", "informational"}:
        return Severity.INFO
    return None


def _score_to_severity(raw: object) -> Severity | None:
    if not isinstance(raw, str) or not raw:
        return None
    s = raw.strip()
    upper = s.upper()
    if upper.startswith("CVSS:3"):
        score = _cvss_v3_base_score(s)
    elif upper.startswith("CVSS:4"):
        score = _cvss_v4_base_score(s)
    else:
        # Plain numeric (e.g. "7.5")
        try:
            score = float(s)
        except ValueError:
            return None
    if score is None:
        return None
    return _bucket_cvss(score)


def _bucket_cvss(score: float) -> Severity:
    """CVSS standard severity rating mapping."""
    if score <= 0.0:
        return Severity.INFO
    if score < 4.0:
        return Severity.LOW
    if score < 7.0:
        return Severity.MEDIUM
    if score < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL


def _parse_vector(vector: str) -> dict[str, str]:
    parts = vector.split("/")
    metrics: dict[str, str] = {}
    for part in parts[1:]:  # skip "CVSS:x.y" prefix
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k.strip()] = v.strip()
    return metrics


# CVSS v3.1 base metric weights (FIRST.org spec).
_V3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_V3_AC = {"L": 0.77, "H": 0.44}
_V3_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # Scope unchanged
_V3_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}   # Scope changed
_V3_UI = {"N": 0.85, "R": 0.62}
_V3_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _cvss_v3_base_score(vector: str) -> float | None:
    m = _parse_vector(vector)
    try:
        av = _V3_AV[m["AV"]]
        ac = _V3_AC[m["AC"]]
        ui = _V3_UI[m["UI"]]
        scope = m["S"]
        pr = (_V3_PR_C if scope == "C" else _V3_PR_U)[m["PR"]]
        c = _V3_CIA[m["C"]]
        i = _V3_CIA[m["I"]]
        a = _V3_CIA[m["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    if scope == "U":
        base = min(impact + exploitability, 10.0)
    else:
        base = min(1.08 * (impact + exploitability), 10.0)
    # Roundup to one decimal, per CVSS spec.
    return _roundup(base)


def _roundup(value: float) -> float:
    import math

    return math.ceil(value * 10) / 10


# CVSS v4.0 macro bucketing. We approximate the official v4 calculator by
# mapping the worst of (Vulnerable / Subsequent) confidentiality / integrity /
# availability impacts to the standard severity bands. This is precise enough
# to match osv.dev's labelled severity in practice.
_V4_IMPACT_RANK = {"H": 3, "L": 2, "N": 0}
_V4_AV_RANK = {"N": 4, "A": 3, "L": 2, "P": 1}
_V4_PR_RANK = {"N": 3, "L": 2, "H": 1}
_V4_UI_RANK = {"N": 3, "P": 2, "A": 1}


def _cvss_v4_base_score(vector: str) -> float | None:
    m = _parse_vector(vector)
    try:
        impacts = [
            _V4_IMPACT_RANK[m["VC"]],
            _V4_IMPACT_RANK[m["VI"]],
            _V4_IMPACT_RANK[m["VA"]],
            _V4_IMPACT_RANK.get(m.get("SC", "N"), 0),
            _V4_IMPACT_RANK.get(m.get("SI", "N"), 0),
            _V4_IMPACT_RANK.get(m.get("SA", "N"), 0),
        ]
        av = _V4_AV_RANK[m["AV"]]
        pr = _V4_PR_RANK[m["PR"]]
        ui = _V4_UI_RANK[m["UI"]]
        ac_easy = m.get("AC", "L") == "L"
        at_none = m.get("AT", "N") == "N"
    except KeyError:
        return None

    max_impact = max(impacts)
    if max_impact == 0:
        return 0.0

    # Baseline from worst impact: H=7, L=4, N=0.
    base = {3: 7.0, 2: 4.0, 0: 0.0}[max_impact]
    # Reachability/exploitability boosts.
    base += 0.5 * (av - 1)              # network/adjacent/local/physical
    base += 0.4 * (pr - 1)              # privileges required
    base += 0.3 * (ui - 1)              # user interaction
    if ac_easy:
        base += 0.2
    if at_none:
        base += 0.2
    # Stack a small bonus if multiple impact dimensions are H/L.
    high_count = sum(1 for v in impacts if v == 3)
    low_count = sum(1 for v in impacts if v == 2)
    base += 0.4 * max(high_count - 1, 0)
    base += 0.2 * max(low_count - 1, 0)

    return _roundup(min(base, 10.0))


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
