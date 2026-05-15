"""Pipeline ABCs and the orchestrator that runs collect -> enrich -> analyze."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from snitch.config import Config

from .findings import Finding, InstalledPackage
from .progress import NullReporter, ProgressReporter

log = logging.getLogger("snitch.orchestrator")


def _snitch_source_root() -> Path | None:
    """Return the directory housing snitch's own source, if discoverable.

    When snitch is run from a checkout (the typical case during development
    and the case that originally produced thousands of self-detections),
    this resolves to the project root containing ``src/snitch/``. When
    snitch is installed as a wheel into ``site-packages``, the parents
    chain still resolves but won't match any package the user has installed
    elsewhere, so the comparison harmlessly falls through.
    """
    try:
        import snitch as _snitch_pkg  # local import; cheap
    except Exception:
        return None
    pkg_file = getattr(_snitch_pkg, "__file__", None)
    if not pkg_file:
        return None
    try:
        # .../<root>/src/snitch/__init__.py -> .../<root>
        return Path(pkg_file).resolve().parents[2]
    except (IndexError, OSError):
        return None


def _is_under(child: Path, parent: Path) -> bool:
    try:
        child_resolved = child.resolve()
    except OSError:
        return False
    try:
        child_resolved.relative_to(parent)
        return True
    except ValueError:
        return False


def _package_belongs_to(package: InstalledPackage, root: Path) -> bool:
    """True when every on-disk root of ``package`` lives under ``root``."""
    raw_roots = (package.extras or {}).get("roots")
    candidates: list[Path] = []
    if raw_roots:
        for r in raw_roots:
            try:
                candidates.append(Path(r))
            except Exception:
                continue
    elif package.location is not None:
        candidates.append(package.location)
    if not candidates:
        return False
    return all(_is_under(c, root) for c in candidates)


class Collector(ABC):
    """Discovers installed packages for a single ecosystem."""

    ecosystem: str = ""

    @abstractmethod
    def collect(self) -> list[InstalledPackage]:
        ...

    def available(self) -> bool:
        """Override to short-circuit when a tool isn't installed."""
        return True


class IntelSource(ABC):
    """Cross-references packages against known-bad data sources."""

    name: str = ""

    @abstractmethod
    def lookup(self, packages: Sequence[InstalledPackage]) -> list[Finding]:
        ...


class Analyzer(ABC):
    """Inspects on-disk content of a package (heuristics or static)."""

    name: str = ""

    @abstractmethod
    def analyze(self, package: InstalledPackage) -> list[Finding]:
        ...


@dataclass
class ScanResult:
    packages: list[InstalledPackage] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def by_severity(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for f in self.findings:
            out.setdefault(f.severity.label, []).append(f)
        return out


@dataclass
class Orchestrator:
    config: Config
    collectors: list[Collector] = field(default_factory=list)
    intel_sources: list[IntelSource] = field(default_factory=list)
    analyzers: list[Analyzer] = field(default_factory=list)

    def run(
        self,
        ecosystems: Iterable[str] | None = None,
        deep: bool = False,
        reporter: ProgressReporter | None = None,
    ) -> ScanResult:
        result = ScanResult()
        wanted = {e for e in (ecosystems or [])} or None
        rep: ProgressReporter = reporter or NullReporter()

        active_collectors = [
            c for c in self.collectors if not (wanted and c.ecosystem not in wanted)
        ]
        rep.start_phase("collect", total=len(active_collectors))
        for collector in active_collectors:
            rep.update(label=collector.ecosystem, advance=0)
            if not collector.available():
                result.skipped.append(f"{collector.ecosystem} (not available)")
                rep.note(f"skip {collector.ecosystem} (not available)")
                rep.update(advance=1)
                continue
            try:
                pkgs = collector.collect()
            except Exception as exc:  # collectors must never crash the run
                log.warning("collector %s failed: %s", collector.ecosystem, exc)
                result.skipped.append(f"{collector.ecosystem} (error: {exc})")
                rep.note(f"{collector.ecosystem} failed: {exc}")
                rep.update(advance=1)
                continue
            log.debug("%s: %d packages", collector.ecosystem, len(pkgs))
            result.packages.extend(pkgs)
            rep.update(label=f"{collector.ecosystem} ({len(pkgs)})", advance=1)
        rep.end_phase()

        if result.packages:
            rep.start_phase("intel", total=len(self.intel_sources))
            for source in self.intel_sources:
                rep.update(label=source.name, advance=0)
                try:
                    result.findings.extend(source.lookup(result.packages))
                except Exception as exc:
                    log.warning("intel %s failed: %s", source.name, exc)
                    rep.note(f"intel {source.name} failed: {exc}")
                rep.update(advance=1)
            rep.end_phase()

        if deep and self.analyzers and result.packages:
            self_root = _snitch_source_root()
            packages_to_analyze = [
                p
                for p in result.packages
                if not (self_root and _package_belongs_to(p, self_root))
            ]
            total = len(packages_to_analyze) * len(self.analyzers)
            rep.start_phase("analyze", total=total)
            for pkg in packages_to_analyze:
                for analyzer in self.analyzers:
                    rep.update(
                        label=f"{analyzer.name} · {pkg.ecosystem}:{pkg.name}",
                        advance=0,
                    )
                    try:
                        result.findings.extend(analyzer.analyze(pkg))
                    except Exception as exc:
                        log.debug("analyzer %s/%s failed: %s", analyzer.name, pkg.key, exc)
                    rep.update(advance=1)
            rep.end_phase()

        from .scoring import score_findings

        score_findings(result.findings)
        return result
