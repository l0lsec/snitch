"""Optional VirusTotal hash lookup for binaries.

We never upload files; we only ask VT whether it's seen the hash before. The
lookup is gated behind ``SNITCH_VT_API_KEY`` and runs against the v3 API.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

import httpx

from snitch.config import Config
from snitch.core.cache import Cache
from snitch.core.findings import Ecosystem, Evidence, Finding, InstalledPackage, Severity
from snitch.core.orchestrator import IntelSource

log = logging.getLogger("snitch.intel.virustotal")

API_BASE = "https://www.virustotal.com/api/v3"
HASH_TTL_SECONDS = 60 * 60 * 24 * 7  # 7 days


class VirusTotalIntel(IntelSource):
    name = "virustotal"

    def __init__(
        self,
        config: Config,
        cache: Cache,
        client: httpx.Client | None = None,
    ):
        self.config = config
        self.cache = cache
        self._owns_client = client is None
        if config.vt_api_key is None:
            self.client = None
        else:
            self.client = client or httpx.Client(
                base_url=API_BASE,
                headers={
                    "x-apikey": config.vt_api_key,
                    "User-Agent": config.user_agent,
                },
                timeout=20.0,
            )

    def close(self) -> None:
        if self._owns_client and self.client is not None:
            self.client.close()

    def lookup(self, packages: Sequence[InstalledPackage]) -> list[Finding]:
        if self.client is None:
            return []
        out: list[Finding] = []
        for pkg in packages:
            if pkg.ecosystem != Ecosystem.BINARY:
                continue
            sha = (pkg.extras or {}).get("sha256")
            if not sha:
                continue
            verdict = self._lookup_hash(sha)
            if verdict is None:
                continue
            malicious = int(verdict.get("malicious", 0))
            suspicious = int(verdict.get("suspicious", 0))
            if malicious == 0 and suspicious == 0:
                continue
            severity = (
                Severity.CRITICAL
                if malicious >= 3
                else Severity.HIGH
                if malicious > 0
                else Severity.MEDIUM
            )
            out.append(
                Finding(
                    package=pkg,
                    rule_id="vt.hash-flagged",
                    title=f"VirusTotal: {malicious} engines flag this hash as malicious",
                    severity=severity,
                    description=(
                        f"SHA-256 {sha} has {malicious} malicious / {suspicious} "
                        "suspicious detections on VirusTotal."
                    ),
                    evidence=[
                        Evidence(
                            kind="ioc",
                            summary=f"VT detections: {malicious} malicious, {suspicious} suspicious",
                            source="virustotal.com",
                            url=f"https://www.virustotal.com/gui/file/{sha}",
                        )
                    ],
                )
            )
        return out

    def _lookup_hash(self, sha: str) -> dict | None:
        cached = self.cache.get_hash(sha, HASH_TTL_SECONDS)
        if cached:
            try:
                import json

                return json.loads(cached["detail_json"]) if cached["detail_json"] else None
            except Exception:
                return None
        try:
            resp = self.client.get(f"/files/{sha}")
        except httpx.HTTPError as exc:
            log.debug("VT lookup failed for %s: %s", sha, exc)
            return None
        if resp.status_code == 404:
            self.cache.put_hash(sha, "virustotal", "unknown", {})
            return None
        if resp.status_code == 401:
            log.warning("VirusTotal API key rejected; disabling further lookups")
            self.client = None
            return None
        if resp.status_code != 200:
            return None
        data = resp.json().get("data", {})
        attrs = data.get("attributes", {}) or {}
        stats = attrs.get("last_analysis_stats", {}) or {}
        verdict = "clean" if stats.get("malicious", 0) == 0 else "malicious"
        self.cache.put_hash(sha, "virustotal", verdict, stats)
        return stats
