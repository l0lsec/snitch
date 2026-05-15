"""Combine signals from multiple sources into a single severity score."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from .findings import Finding, Severity

WEIGHTS = {
    "advisory": 60,
    "malicious-packages": 80,
    "ioc": 40,
    "rule": 20,
    "ast": 25,
    "metadata": 10,
}

# Evidence kinds that represent third-party intel (someone else has already
# said this package is bad). Only these are trusted enough to upgrade an
# entire package's findings to higher severities; static heuristics on their
# own can stack to large totals on perfectly innocent libraries.
INTEL_EVIDENCE_KINDS = frozenset({"advisory", "malicious-packages"})


def score_finding(finding: Finding) -> int:
    """Score a single finding based on attached evidence and base severity."""
    base = {
        Severity.INFO: 5,
        Severity.LOW: 15,
        Severity.MEDIUM: 35,
        Severity.HIGH: 65,
        Severity.CRITICAL: 90,
    }[finding.severity]
    for ev in finding.evidence:
        base += WEIGHTS.get(ev.kind, 5)
    return min(base, 100)


def score_findings(findings: Iterable[Finding]) -> None:
    """Set ``score`` and upgrade severity when intel signals corroborate.

    Earlier versions promoted *any* package to CRITICAL once its findings
    accumulated a high enough total score. That made every mature library
    look critical because static AST/IOC hits stack quickly. We now only
    promote when at least one finding in the same package has intel-class
    evidence (advisory / malicious-packages); heuristics alone can never
    auto-promote.
    """

    findings = list(findings)
    for f in findings:
        f.score = score_finding(f)

    by_pkg: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_pkg[f.package.key].append(f)

    for pkg_findings in by_pkg.values():
        if len(pkg_findings) < 2:
            continue
        has_intel = any(
            ev.kind in INTEL_EVIDENCE_KINDS for f in pkg_findings for ev in f.evidence
        )
        if not has_intel:
            continue
        total = sum(f.score for f in pkg_findings)
        if total >= 120:
            for f in pkg_findings:
                if f.severity < Severity.HIGH:
                    f.severity = Severity.HIGH
        if total >= 200:
            for f in pkg_findings:
                f.severity = Severity.CRITICAL
