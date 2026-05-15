"""Wire up collectors / intel sources / analyzers based on selection."""

from __future__ import annotations

from collections.abc import Iterable

from .config import Config
from .core.cache import Cache
from .core.findings import Ecosystem
from .core.orchestrator import Analyzer, Collector, IntelSource, Orchestrator


def build_collectors(ecosystems: Iterable[str] | None = None) -> list[Collector]:
    from .collectors.binaries import BinariesCollector
    from .collectors.brew import BrewCollector
    from .collectors.github_repos import GithubReposCollector
    from .collectors.go import GoCollector
    from .collectors.npm import NpmCollector
    from .collectors.pip import PipCollector
    from .collectors.vscode import VSCodeCollector

    all_collectors: list[Collector] = [
        PipCollector(),
        NpmCollector(),
        BrewCollector(),
        GoCollector(),
        VSCodeCollector(),
        BinariesCollector(),
        GithubReposCollector(),
    ]
    if ecosystems is None:
        return all_collectors
    wanted = {Ecosystem.normalize(e) for e in ecosystems}
    return [c for c in all_collectors if c.ecosystem in wanted]


def build_intel(config: Config, cache: Cache) -> list[IntelSource]:
    from .intel.malicious_packages import MaliciousPackagesIntel
    from .intel.osv import OSVIntel
    from .intel.typosquat import TyposquatIntel
    from .intel.virustotal import VirusTotalIntel

    sources: list[IntelSource] = [
        MaliciousPackagesIntel(config, cache),
        OSVIntel(config, cache),
        TyposquatIntel(config, cache),
    ]
    if config.vt_api_key:
        sources.append(VirusTotalIntel(config, cache))
    return sources


def build_analyzers() -> list[Analyzer]:
    from .analyzers.js_ast import JsAstAnalyzer
    from .analyzers.patterns import IocPatternAnalyzer
    from .analyzers.py_ast import PyAstAnalyzer
    from .heuristics.npm_rules import NpmHeuristicAnalyzer
    from .heuristics.pip_rules import PipHeuristicAnalyzer

    return [
        NpmHeuristicAnalyzer(),
        PipHeuristicAnalyzer(),
        IocPatternAnalyzer(),
        JsAstAnalyzer(),
        PyAstAnalyzer(),
    ]


def build_orchestrator(
    config: Config,
    cache: Cache,
    ecosystems: Iterable[str] | None = None,
    deep: bool = False,
) -> Orchestrator:
    return Orchestrator(
        config=config,
        collectors=build_collectors(ecosystems),
        intel_sources=build_intel(config, cache),
        analyzers=build_analyzers() if deep else [],
    )
