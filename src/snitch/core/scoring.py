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
    """Set ``score`` and (carefully) upgrade severity when corroborated.

    A finding's severity must always reflect what its own evidence actually
    reports. In particular, multiple OSV advisories on the same package are
    *not* corroboration of each other -- each one already carries the
    severity assigned by the upstream database, and stacking them must not
    silently promote mediums to critical.

    We therefore only escalate a finding's severity when an *independent*
    heuristic signal (``ast``/``ioc``/``rule``) lands on the same package as
    intel-class evidence (``advisory``/``malicious-packages``). Even then we
    cap the upgrade at ``HIGH`` and never above any advisory's reported
    severity for that package.
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

        evidence_kinds = {
            ev.kind for f in pkg_findings for ev in f.evidence
        }
        has_intel = bool(evidence_kinds & INTEL_EVIDENCE_KINDS)
        has_heuristic = bool(evidence_kinds & {"ast", "ioc", "rule"})
        if not (has_intel and has_heuristic):
            continue

        # Cap any escalation at the highest severity reported by intel
        # evidence on this package -- never invent a severity higher than
        # what an advisory itself states.
        intel_ceiling = max(
            (f.severity for f in pkg_findings
             if any(ev.kind in INTEL_EVIDENCE_KINDS for ev in f.evidence)),
            default=Severity.MEDIUM,
        )
        target = min(Severity.HIGH, intel_ceiling)
        for f in pkg_findings:
            if f.severity < target:
                f.severity = target
