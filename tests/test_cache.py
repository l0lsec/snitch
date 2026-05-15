from snitch.core.cache import Cache


def test_advisory_roundtrip(cache: Cache) -> None:
    cache.upsert_advisory(
        advisory_id="GHSA-1234",
        ecosystem="npm",
        name="evil",
        summary="bad",
        severity="HIGH",
        affected=[{"package": {"name": "evil", "ecosystem": "npm"}}],
        references=[{"url": "https://example.com"}],
        raw={"id": "GHSA-1234"},
    )
    rows = cache.advisories_for("npm", "Evil")
    assert len(rows) == 1
    assert rows[0]["id"] == "GHSA-1234"
    assert rows[0]["severity"] == "HIGH"


def test_query_cache_ttl(cache: Cache) -> None:
    cache.put_query("k", {"a": 1})
    assert cache.get_query("k", 1000) == {"a": 1}
    # negative TTL forces miss
    assert cache.get_query("k", -1) is None


def test_malicious_count_and_reset(cache: Cache) -> None:
    cache.upsert_malicious(
        advisory_id="MAL-1",
        ecosystem="npm",
        name="x",
        summary=None,
        published=None,
        modified=None,
        source=None,
        raw={"id": "MAL-1"},
    )
    assert cache.malicious_count() == 1
    cache.reset_malicious()
    assert cache.malicious_count() == 0
