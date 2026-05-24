from snitch.core.findings import Ecosystem, Evidence, Finding, InstalledPackage, Severity
from snitch.core.scoring import score_finding, score_findings


def test_severity_lookup() -> None:
    assert Severity.from_str("HIGH") == Severity.HIGH
    assert Severity.from_str("warning") == Severity.MEDIUM
    assert Severity.from_str(None) == Severity.MEDIUM


def test_ecosystem_normalize() -> None:
    assert Ecosystem.normalize("pip") == Ecosystem.PYPI
    assert Ecosystem.normalize("homebrew") == Ecosystem.HOMEBREW
    assert Ecosystem.normalize("cursor") == Ecosystem.VSCODE


def _pkg() -> InstalledPackage:
    return InstalledPackage(ecosystem=Ecosystem.NPM, name="evil", version="1.0.0")


def test_score_finding_uses_evidence_weight() -> None:
    f = Finding(
        package=_pkg(),
        rule_id="x",
        title="t",
        severity=Severity.LOW,
        description="d",
        evidence=[Evidence(kind="advisory", summary="s")],
    )
    assert score_finding(f) > 50  # base 15 + 60 advisory


def test_heuristic_only_signals_do_not_auto_upgrade() -> None:
    """Heuristic/AST/IOC signals stacking on a single package must NOT
    auto-promote severity. Only third-party intel does that. This is the
    fix for the false-positive flood where every PyPI package with a few
    legitimate ``subprocess.run`` calls ended up labeled ``critical``.
    """
    pkg = _pkg()
    f1 = Finding(pkg, "r1", "a", Severity.MEDIUM, "", [Evidence("rule", "x")])
    f2 = Finding(pkg, "r2", "b", Severity.MEDIUM, "", [Evidence("ast", "y")])
    f3 = Finding(pkg, "r3", "c", Severity.MEDIUM, "", [Evidence("ioc", "z")])
    score_findings([f1, f2, f3])
    assert f1.severity == Severity.MEDIUM
    assert f2.severity == Severity.MEDIUM
    assert f3.severity == Severity.MEDIUM


def test_intel_corroboration_upgrades_severity() -> None:
    """When at least one finding carries intel evidence, stacked findings
    on the same package may be promoted to HIGH/CRITICAL.
    """
    pkg = _pkg()
    advisory = Finding(
        pkg, "r1", "a", Severity.HIGH, "", [Evidence("advisory", "CVE-X")]
    )
    heuristic = Finding(
        pkg, "r2", "b", Severity.MEDIUM, "", [Evidence("ast", "y")]
    )
    score_findings([advisory, heuristic])
    assert heuristic.severity >= Severity.HIGH


def test_multiple_medium_advisories_stay_medium() -> None:
    """Three OSV advisories on the same package are not corroboration of
    each other. Each one's severity must reflect what its source reports;
    stacking three mediums must NOT yield a critical.
    """
    pkg = _pkg()
    advisories = [
        Finding(pkg, f"osv.advisory.{i}", f"GHSA-{i}", Severity.MEDIUM, "",
                [Evidence("advisory", f"GHSA-{i}", source="osv.dev")])
        for i in range(3)
    ]
    score_findings(advisories)
    for f in advisories:
        assert f.severity == Severity.MEDIUM


def test_intel_ceiling_caps_heuristic_upgrade() -> None:
    """A heuristic finding on a package whose only intel is a MEDIUM
    advisory must not be promoted past MEDIUM -- the advisory itself is
    the ceiling.
    """
    pkg = _pkg()
    advisory = Finding(
        pkg, "osv.advisory", "GHSA-X", Severity.MEDIUM, "",
        [Evidence("advisory", "GHSA-X", source="osv.dev")],
    )
    heuristic = Finding(
        pkg, "rule.x", "x", Severity.LOW, "", [Evidence("ast", "y")]
    )
    score_findings([advisory, heuristic])
    assert advisory.severity == Severity.MEDIUM
    assert heuristic.severity == Severity.MEDIUM
