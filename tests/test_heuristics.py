from pathlib import Path

from snitch.collectors.npm import NpmCollector
from snitch.core.findings import Ecosystem, InstalledPackage, Severity
from snitch.heuristics.npm_rules import NpmHeuristicAnalyzer
from snitch.heuristics.pip_rules import PipHeuristicAnalyzer


def test_npm_postinstall_flagged_high(npm_pkg_dir: Path) -> None:
    pkg = NpmCollector._read_package_json(npm_pkg_dir)
    assert pkg is not None
    findings = NpmHeuristicAnalyzer().analyze(pkg)
    assert any(f.rule_id == "npm.lifecycle-script" for f in findings)
    fl = next(f for f in findings if f.rule_id == "npm.lifecycle-script")
    assert fl.severity >= Severity.HIGH


def test_pip_setup_py_flagged(pip_pkg_dir: Path) -> None:
    pkg = InstalledPackage(
        ecosystem=Ecosystem.PYPI,
        name="evilpy",
        version="0.1.0",
        location=pip_pkg_dir,
    )
    findings = PipHeuristicAnalyzer().analyze(pkg)
    assert any(f.rule_id == "pip.setup-suspicious" for f in findings)
