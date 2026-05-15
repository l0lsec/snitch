from pathlib import Path

from snitch.analyzers.js_ast import JsAstAnalyzer
from snitch.analyzers.patterns import IocPatternAnalyzer
from snitch.analyzers.py_ast import PyAstAnalyzer
from snitch.core.findings import Ecosystem, InstalledPackage


def test_js_ast_flags_eval_and_child_process(npm_pkg_dir: Path) -> None:
    pkg = InstalledPackage(
        ecosystem=Ecosystem.NPM,
        name="evil",
        version="1.0.0",
        location=npm_pkg_dir,
    )
    findings = JsAstAnalyzer().analyze(pkg)
    rule_ids = {f.rule_id for f in findings}
    assert "js.eval" in rule_ids
    assert "js.child-process" in rule_ids


def test_py_ast_flags_exec_and_subprocess(pip_pkg_dir: Path) -> None:
    pkg = InstalledPackage(
        ecosystem=Ecosystem.PYPI,
        name="evilpy",
        version="0.1.0",
        location=pip_pkg_dir,
    )
    findings = PyAstAnalyzer().analyze(pkg)
    rule_ids = {f.rule_id for f in findings}
    assert "py.exec" in rule_ids
    assert "py.subprocess" in rule_ids


def test_ioc_patterns_match(npm_pkg_dir: Path) -> None:
    pkg = InstalledPackage(
        ecosystem=Ecosystem.NPM,
        name="evil",
        version="1.0.0",
        location=npm_pkg_dir,
    )
    findings = IocPatternAnalyzer().analyze(pkg)
    assert any(f.rule_id == "ioc.curl-pipe-shell" for f in findings)
