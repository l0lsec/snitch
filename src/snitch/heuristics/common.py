"""Heuristic helpers shared across ecosystems."""

from __future__ import annotations

from snitch.core.findings import Evidence, Finding, InstalledPackage, Severity


def make_finding(
    pkg: InstalledPackage,
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    evidence: list[Evidence] | None = None,
    references: list[str] | None = None,
) -> Finding:
    return Finding(
        package=pkg,
        rule_id=rule_id,
        title=title,
        severity=severity,
        description=description,
        evidence=evidence or [],
        references=references or [],
    )


def levenshtein(a: str, b: str) -> int:
    """Iterative DP Levenshtein distance. Cheap enough for short package names."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    cur = [0] * (len(b) + 1)
    for i, ca in enumerate(a, start=1):
        cur[0] = i
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            cur[j] = min(
                cur[j - 1] + 1,
                prev[j] + 1,
                prev[j - 1] + cost,
            )
        prev, cur = cur, prev
    return prev[-1]
