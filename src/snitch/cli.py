"""Top-level CLI for snitch."""

from __future__ import annotations

import logging
import time
from pathlib import Path

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from . import __version__
from .config import Config, Paths, migrate_xdg_to_app_local
from .core.cache import Cache
from .core.findings import Ecosystem, InstalledPackage
from .core.progress import RichProgressReporter
from .core.report import (
    render_html,
    render_json,
    render_markdown,
    render_terminal,
    write_findings_list,
)
from .ignore import IgnoreList
from .registry import build_collectors, build_intel, build_orchestrator

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Scan locally-installed tools and packages for malicious code.",
)
ignore_app = typer.Typer(help="Manage the allow-list.", no_args_is_help=True)
app.add_typer(ignore_app, name="ignore")

console = Console()


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_path=False, rich_tracebacks=True)],
    )


def _parse_ecosystems(raw: str | None) -> list[str] | None:
    if not raw:
        return None
    return [Ecosystem.normalize(p.strip()) for p in raw.split(",") if p.strip()]


# ---------------------------------------------------------------------------
# version
# ---------------------------------------------------------------------------


@app.command()
def version() -> None:
    """Print snitch's version."""
    console.print(f"snitch {__version__}")


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


@app.command()
def scan(
    ecosystem: str = typer.Option(
        None,
        "--ecosystem",
        "-e",
        help="Comma-separated ecosystems to scan (npm,pip,brew,go,vscode,binaries,github).",
    ),
    deep: bool = typer.Option(
        False, "--deep", help="Run heuristic + static analyzers on package contents."
    ),
    output: Path = typer.Option(
        None, "--out", "-o", help="Write the report to this file (format inferred)."
    ),
    fmt: str = typer.Option(
        "terminal",
        "--format",
        "-f",
        help="Report format: terminal | md | json | html.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Inventory installed packages and check them against intel + heuristics."""
    _setup_logging(verbose)
    config = Config.from_env()
    selected = _parse_ecosystems(ecosystem)
    started = int(time.time())
    started_perf = time.perf_counter()

    with Cache(config.paths.db_path) as cache:
        orchestrator = build_orchestrator(config, cache, selected, deep=deep)
        ignore_list = IgnoreList(config.paths.ignore_file)

        note_sink = (lambda msg: console.log(f"[dim]{msg}[/dim]")) if verbose else None
        with RichProgressReporter(console, on_note=note_sink) as reporter:
            result = orchestrator.run(
                ecosystems=selected,
                deep=deep,
                reporter=reporter,
            )
        result.findings = ignore_list.filter(result.findings)

        elapsed = time.perf_counter() - started_perf
        ecosystems_used = sorted({p.ecosystem for p in result.packages})
        console.print(
            f"[dim]scanned {len(result.packages)} packages across "
            f"{len(ecosystems_used)} ecosystems in {elapsed:.1f}s "
            f"· {len(result.findings)} findings[/dim]"
        )
        cache.record_scan(
            ecosystems=ecosystems_used,
            package_count=len(result.packages),
            finding_count=len(result.findings),
            payload=write_findings_list(result.findings),
            started_at=started,
        )

    if fmt == "terminal":
        render_terminal(result, console)
        if output:
            console.print("[yellow]--out ignored for terminal format[/yellow]")
    elif fmt == "md":
        text = render_markdown(result)
        _emit(text, output, "report.md")
    elif fmt == "json":
        text = render_json(result)
        _emit(text, output, "report.json")
    elif fmt == "html":
        text = render_html(result)
        _emit(text, output, "report.html")
    else:
        raise typer.BadParameter(f"unknown format: {fmt}")

    if any(f.severity.label in {"critical", "high"} for f in result.findings):
        raise typer.Exit(code=2)


def _emit(content: str, output: Path | None, default_name: str) -> None:
    if output is None:
        console.print(content)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")
    console.print(f"[green]wrote[/green] {output}")


# ---------------------------------------------------------------------------
# inventory
# ---------------------------------------------------------------------------


@app.command()
def inventory(
    ecosystem: str = typer.Option(None, "--ecosystem", "-e"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """List discovered packages without doing any cross-referencing."""
    _setup_logging(verbose)
    selected = _parse_ecosystems(ecosystem)
    collectors = build_collectors(selected)
    table = Table(title="Inventory")
    table.add_column("ecosystem")
    table.add_column("name")
    table.add_column("version")
    table.add_column("location", overflow="fold")
    total = 0
    note_sink = (lambda msg: console.log(f"[dim]{msg}[/dim]")) if verbose else None
    with RichProgressReporter(console, on_note=note_sink) as reporter:
        reporter.start_phase("collect", total=len(collectors))
        for c in collectors:
            reporter.update(label=c.ecosystem, advance=0)
            if not c.available():
                reporter.note(f"skip {c.ecosystem} (not available)")
                reporter.update(advance=1)
                continue
            try:
                packages = c.collect()
            except Exception as exc:
                reporter.note(f"{c.ecosystem} failed: {exc}")
                reporter.update(advance=1)
                continue
            for p in packages:
                total += 1
                table.add_row(p.ecosystem, p.name, p.version or "", str(p.location or ""))
            reporter.update(label=f"{c.ecosystem} ({len(packages)})", advance=1)
        reporter.end_phase()
    console.print(table)
    console.print(f"{total} packages")


# ---------------------------------------------------------------------------
# update
# ---------------------------------------------------------------------------


@app.command()
def update(verbose: bool = typer.Option(False, "--verbose", "-v")) -> None:
    """Refresh local advisory + malicious-package mirrors."""
    _setup_logging(verbose)
    config = Config.from_env()
    with Cache(config.paths.db_path) as cache:
        from .intel.malicious_packages import MaliciousPackagesIntel

        mp = MaliciousPackagesIntel(config, cache)
        with console.status("syncing ossf/malicious-packages…"):
            ok, msg = mp.update_mirror()
        if ok:
            console.print(f"[green]✓ malicious-packages: {msg}[/green]")
        else:
            console.print(f"[red]✗ malicious-packages: {msg}[/red]")
        console.print(
            "[dim]OSV.dev advisories are fetched on demand and cached locally.[/dim]"
        )


# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------


@app.command()
def inspect(
    target: str = typer.Argument(..., help="ecosystem:name[@version] (e.g. pip:requests@2.31.0)"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Run a focused scan against a single named package."""
    _setup_logging(verbose)
    if ":" not in target:
        raise typer.BadParameter("expected ecosystem:name[@version]")
    eco_raw, rest = target.split(":", 1)
    eco = Ecosystem.normalize(eco_raw)
    if "@" in rest:
        name, version = rest.rsplit("@", 1)
    else:
        name, version = rest, None
    pkg = InstalledPackage(ecosystem=eco, name=name, version=version)
    config = Config.from_env()
    with Cache(config.paths.db_path) as cache:
        intel_sources = build_intel(config, cache)
        findings = []
        for source in intel_sources:
            try:
                findings.extend(source.lookup([pkg]))
            except Exception as exc:
                console.log(f"[yellow]{source.name} failed: {exc}[/yellow]")
    if not findings:
        console.print(f"[green]No intel hits for {pkg.key}[/green]")
        return
    for f in findings:
        console.print(f"[bold]{f.severity.label}[/bold] {f.rule_id} — {f.title}")
        if f.description:
            console.print(f"  {f.description}")
        for ev in f.evidence:
            console.print(f"  • {ev.summary}")
            if ev.url:
                console.print(f"    {ev.url}")


# ---------------------------------------------------------------------------
# report (re-render last scan)
# ---------------------------------------------------------------------------


@app.command()
def report(
    fmt: str = typer.Option("md", "--format", "-f", help="md | json | html"),
    output: Path = typer.Option(None, "--out", "-o"),
) -> None:
    """Re-render the most recent scan from cache."""
    config = Config.from_env()
    with Cache(config.paths.db_path) as cache:
        row = cache.conn.execute(
            "SELECT * FROM scan_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
    if row is None:
        console.print("[yellow]No scan history yet. Run `snitch scan` first.[/yellow]")
        raise typer.Exit(1)
    import json as _json

    findings = _json.loads(row["payload_json"]) if row["payload_json"] else []
    lines = [
        "# snitch report (cached)",
        "",
        f"_scan started <t:{row['started_at']}>_",
        "",
        f"- ecosystems: {row['ecosystems']}",
        f"- packages: {row['package_count']}",
        f"- findings: {row['finding_count']}",
        "",
    ]
    for f in findings:
        lines.append(f"## {f['package']} — {f['title']}")
        lines.append(f"- rule: `{f['rule_id']}`  · severity: {f['severity']}  · score: {f['score']}")
        for e in f.get("evidence", []):
            lines.append(f"  - {e}")
        lines.append("")
    text = "\n".join(lines)
    if fmt == "json":
        text = _json.dumps(findings, indent=2)
    elif fmt == "html":
        from html import escape

        text = (
            "<!doctype html><html><body><pre>"
            + escape(text)
            + "</pre></body></html>"
        )
    _emit(text, output, f"report.{fmt}")


# ---------------------------------------------------------------------------
# where / migrate
# ---------------------------------------------------------------------------


@app.command()
def where() -> None:
    """Show where snitch reads and writes its data."""
    paths = Paths.discover()
    xdg = Paths.xdg()
    mode = "app-local" if paths.is_app_local else "XDG (fallback)"
    table = Table(title=f"snitch data ({mode})")
    table.add_column("kind")
    table.add_column("path", overflow="fold")
    table.add_column("exists", justify="center")
    table.add_row("cache dir", str(paths.cache_dir), "yes" if paths.cache_dir.exists() else "no")
    table.add_row("db", str(paths.db_path), "yes" if paths.db_path.exists() else "no")
    table.add_row("mirror", str(paths.ossf_mirror), "yes" if paths.ossf_mirror.exists() else "no")
    table.add_row("ignore", str(paths.ignore_file), "yes" if paths.ignore_file.exists() else "no")
    console.print(table)

    if paths.project_root:
        console.print(f"[dim]project root:[/dim] {paths.project_root}")
    else:
        console.print(
            "[dim]no project root discovered "
            "(snitch is installed as a wheel; using XDG paths).[/dim]"
        )

    legacy_present = any(
        (
            xdg.db_path.exists(),
            xdg.ossf_mirror.exists(),
            xdg.ignore_file.exists(),
        )
    ) and (xdg.cache_dir != paths.cache_dir)
    if legacy_present:
        console.print(
            f"[yellow]Legacy XDG data still present at {xdg.cache_dir}.[/yellow] "
            "Run `snitch migrate` to move it into the app-local directory."
        )


@app.command()
def migrate(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would move, don't move."),
) -> None:
    """Move legacy XDG-cached data into the app-local directory."""
    target = Paths.discover()
    source = Paths.xdg()
    if not target.is_app_local:
        console.print(
            "[yellow]No app-local directory available "
            "(snitch couldn't find its project root or it isn't writable).[/yellow]"
        )
        raise typer.Exit(1)
    if target.cache_dir == source.cache_dir:
        console.print("[green]Already using XDG paths; nothing to migrate.[/green]")
        return

    legacy_items: list[tuple[str, Path, Path]] = []
    if source.db_path.exists():
        legacy_items.append(("db", source.db_path, target.db_path))
    if source.ossf_mirror.exists():
        legacy_items.append(("mirror", source.ossf_mirror, target.ossf_mirror))
    if source.ignore_file.exists():
        legacy_items.append(("ignore", source.ignore_file, target.ignore_file))

    if not legacy_items:
        console.print("[green]No legacy XDG data found; nothing to migrate.[/green]")
        return

    for label, src, dst in legacy_items:
        console.print(f"[dim]{label}:[/dim] {src} -> {dst}")

    if dry_run:
        console.print("[yellow]--dry-run set; no files were moved.[/yellow]")
        return

    target.ensure()
    result = migrate_xdg_to_app_local(target, source)
    moved = sum(
        [
            int(result.moved_db),
            int(result.moved_mirror),
            int(result.moved_ignore),
        ]
    )
    console.print(f"[green]Migrated {moved} item(s).[/green]")
    if result.error:
        console.print(f"[red]error: {result.error}[/red]")
        raise typer.Exit(2)


# ---------------------------------------------------------------------------
# ignore subcommands
# ---------------------------------------------------------------------------


@ignore_app.command("add")
def ignore_add(
    rule_id: str = typer.Option(None, "--rule"),
    package: str = typer.Option(None, "--package"),
    reason: str = typer.Option(None, "--reason"),
) -> None:
    """Add an allow-list entry. Provide at least one of --rule or --package."""
    if not rule_id and not package:
        raise typer.BadParameter("provide --rule and/or --package")
    config = Config.from_env()
    il = IgnoreList(config.paths.ignore_file)
    il.add(rule_id, package, reason)
    console.print(f"[green]added ignore rule[/green] -> {config.paths.ignore_file}")


@ignore_app.command("list")
def ignore_list_cmd() -> None:
    config = Config.from_env()
    il = IgnoreList(config.paths.ignore_file)
    if not il.rules:
        console.print("(no ignore rules)")
        return
    table = Table()
    table.add_column("rule_id")
    table.add_column("package")
    table.add_column("reason")
    for r in il.rules:
        table.add_row(r.rule_id or "*", r.package or "*", r.reason or "")
    console.print(table)


@ignore_app.command("path")
def ignore_path() -> None:
    """Print the location of the ignore file."""
    console.print(str(Config.from_env().paths.ignore_file))


def main() -> None:  # pragma: no cover - thin wrapper
    app()


if __name__ == "__main__":
    main()
