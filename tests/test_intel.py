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


def test_typosquat_flags_close_names(cache: Cache) -> None:
    pkg = InstalledPackage(ecosystem=Ecosystem.NPM, name="reactt", version="1.0.0")
    intel = TyposquatIntel(Config.from_env(), cache)
    findings = intel.lookup([pkg])
    assert any(f.rule_id == "typosquat.distance" for f in findings)


def test_typosquat_ignores_exact_match(cache: Cache) -> None:
    pkg = InstalledPackage(ecosystem=Ecosystem.NPM, name="react", version="18.0.0")
    intel = TyposquatIntel(Config.from_env(), cache)
    assert intel.lookup([pkg]) == []
