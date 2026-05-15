from pathlib import Path

from snitch.core.findings import Ecosystem, Finding, InstalledPackage, Severity
from snitch.ignore import IgnoreList


def _f(rule: str, name: str = "foo") -> Finding:
    return Finding(
        package=InstalledPackage(ecosystem=Ecosystem.NPM, name=name, version="1.0.0"),
        rule_id=rule,
        title="t",
        severity=Severity.LOW,
        description="",
    )


def test_ignore_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "ignore.toml"
    il = IgnoreList(path)
    il.add(rule_id="npm.lifecycle-script", package=None, reason="ok")
    assert path.exists()

    il2 = IgnoreList(path)
    findings = [_f("npm.lifecycle-script"), _f("npm.obfuscated-entry")]
    kept = il2.filter(findings)
    assert len(kept) == 1
    assert kept[0].rule_id == "npm.obfuscated-entry"


def test_ignore_package_specific(tmp_path: Path) -> None:
    path = tmp_path / "ignore.toml"
    il = IgnoreList(path)
    il.add(rule_id=None, package="npm:foo", reason=None)

    findings = [_f("any", "foo"), _f("any", "bar")]
    kept = IgnoreList(path).filter(findings)
    assert [f.package.name for f in kept] == ["bar"]
