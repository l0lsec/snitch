"""Intel source tests with mocked HTTP."""

from __future__ import annotations

import httpx

from snitch.config import Config
from snitch.core.cache import Cache
from snitch.core.findings import Ecosystem, InstalledPackage, Severity
from snitch.intel.osv import OSVIntel
from snitch.intel.typosquat import TyposquatIntel


def _mock_client(responses: dict[str, dict]) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        body = responses.get(request.url.path)
        if body is None:
            return httpx.Response(404, json={"error": "not mocked"})
        return httpx.Response(200, json=body)

    return httpx.Client(transport=httpx.MockTransport(handler), base_url="https://api.osv.dev")


def test_osv_querybatch_creates_findings(cache: Cache) -> None:
    pkg = InstalledPackage(ecosystem=Ecosystem.NPM, name="evil", version="1.0.0")
    responses = {
        "/v1/querybatch": {
            "results": [{"vulns": [{"id": "MAL-EVIL-1"}]}]
        },
        "/v1/vulns/MAL-EVIL-1": {
            "id": "MAL-EVIL-1",
            "summary": "malicious package evil",
            "details": "x",
            "severity": [{"type": "CVSS_V3", "score": "CRITICAL"}],
            "references": [{"url": "https://example.com"}],
            "affected": [{"package": {"name": "evil", "ecosystem": "npm"}}],
        },
    }
    client = _mock_client(responses)
    intel = OSVIntel(Config.from_env(), cache, client=client)
    findings = intel.lookup([pkg])
    intel.close()
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "osv.malicious"
    assert f.severity == Severity.CRITICAL
    rows = cache.advisories_for("npm", "evil")
    assert rows and rows[0]["id"] == "MAL-EVIL-1"


def _osv_finding(cache: Cache, vuln: dict, vid: str = "OSV-X"):
    pkg = InstalledPackage(ecosystem=Ecosystem.PYPI, name="pip", version="25.3")
    responses = {
        "/v1/querybatch": {"results": [{"vulns": [{"id": vid}]}]},
        f"/v1/vulns/{vid}": {**vuln, "id": vid},
    }
    intel = OSVIntel(Config.from_env(), cache, client=_mock_client(responses))
    findings = intel.lookup([pkg])
    intel.close()
    assert len(findings) == 1
    return findings[0]


def test_osv_uses_database_specific_severity(cache: Cache) -> None:
    """GHSA entries advertise their severity in ``database_specific`` --
    we must trust that label first instead of mis-bucketing CVSS vectors.
    """
    f = _osv_finding(cache, {
        "summary": "moderate finding",
        "database_specific": {"severity": "MODERATE"},
        "severity": [{
            "type": "CVSS_V4",
            # Real GHSA-58qw-9mgm-455v vector -- previously fell through to MEDIUM
            # via the "cvss:" branch; here the database_specific label wins.
            "score": "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
        }],
    })
    assert f.severity == Severity.MEDIUM


def test_osv_parses_cvss_v3_vector(cache: Cache) -> None:
    """No database_specific.severity -> we must compute the bucket from the
    CVSS vector instead of defaulting to MEDIUM."""
    f = _osv_finding(cache, {
        "summary": "low-impact info disclosure",
        # CVSS v3.1 base score 5.3 -> MEDIUM.
        "severity": [{
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        }],
    })
    assert f.severity == Severity.MEDIUM

    f_high = _osv_finding(cache, {
        "summary": "rce",
        # CVSS v3.1 base score 9.8 -> CRITICAL.
        "severity": [{
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }],
    }, vid="OSV-RCE")
    assert f_high.severity == Severity.CRITICAL


def test_osv_falls_back_to_low_label(cache: Cache) -> None:
    f = _osv_finding(cache, {
        "summary": "minor",
        "database_specific": {"severity": "LOW"},
    })
    assert f.severity == Severity.LOW


def test_typosquat_flags_close_names(cache: Cache) -> None:
    pkg = InstalledPackage(ecosystem=Ecosystem.NPM, name="reactt", version="1.0.0")
    intel = TyposquatIntel(Config.from_env(), cache)
    findings = intel.lookup([pkg])
    assert any(f.rule_id == "typosquat.distance" for f in findings)


def test_typosquat_ignores_exact_match(cache: Cache) -> None:
    pkg = InstalledPackage(ecosystem=Ecosystem.NPM, name="react", version="18.0.0")
    intel = TyposquatIntel(Config.from_env(), cache)
    assert intel.lookup([pkg]) == []
