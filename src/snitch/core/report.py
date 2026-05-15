"""Renderers for ScanResult: terminal (rich), markdown, json, html."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .findings import Finding, Severity
from .orchestrator import ScanResult

SEVERITY_COLOR = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}


def _sort_key(f: Finding) -> tuple[int, int, str]:
    return (-int(f.severity), -f.score, f.package.key)


def render_terminal(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()
    findings = sorted(result.findings, key=_sort_key)

    counts = Counter(f.severity.label for f in findings)
    summary = (
        f"[bold]{len(result.packages)}[/bold] packages scanned across "
        f"{len({p.ecosystem for p in result.packages})} ecosystems · "
        f"[bold]{len(findings)}[/bold] findings"
    )
    severity_line = "  ".join(
        f"[{SEVERITY_COLOR[s]}]{s}: {counts.get(s, 0)}[/]"
        for s in ("critical", "high", "medium", "low", "info")
    )
    console.print(Panel(f"{summary}\n{severity_line}", title="snitch scan", expand=False))

    if result.skipped:
        console.print("[dim]skipped: " + ", ".join(result.skipped) + "[/dim]")

    if not findings:
        console.print("[green]No findings. ✓[/green]")
        return

    table = Table(show_lines=False, expand=True)
    table.add_column("sev", width=8)
    table.add_column("score", width=5, justify="right")
    table.add_column("package", overflow="fold")
    table.add_column("rule")
    table.add_column("title", overflow="fold")

    for f in findings:
        sev = Text(f.severity.label, style=SEVERITY_COLOR[f.severity.label])
        table.add_row(sev, str(f.score), f.package.key, f.rule_id, f.title)
    console.print(table)

    grouped: dict[str, list[Finding]] = {}
    for f in findings:
        if f.severity >= Severity.HIGH:
            grouped.setdefault(f.package.key, []).append(f)

    if grouped:
        console.print()
        console.print("[bold]High-priority detail[/bold]")
        for pkg_key, pkg_findings in grouped.items():
            console.print(f"  [bold]{pkg_key}[/bold]")
            for f in pkg_findings:
                console.print(
                    f"    [{SEVERITY_COLOR[f.severity.label]}]{f.severity.label}[/] "
                    f"{f.rule_id}: {f.title}"
                )
                if f.description:
                    console.print(f"      {f.description}")
                for ev in f.evidence[:3]:
                    line = f"      • {ev.kind}: {ev.summary}"
                    if ev.url:
                        line += f"  ({ev.url})"
                    console.print(line)
                if len(f.evidence) > 3:
                    console.print(f"      … +{len(f.evidence) - 3} more")


def render_markdown(result: ScanResult) -> str:
    findings = sorted(result.findings, key=_sort_key)
    counts = Counter(f.severity.label for f in findings)
    out: list[str] = []
    out.append("# snitch report")
    out.append("")
    out.append(f"_generated {datetime.now(UTC).isoformat(timespec='seconds')}_")
    out.append("")
    out.append(
        f"- packages scanned: **{len(result.packages)}**\n"
        f"- ecosystems: **{len({p.ecosystem for p in result.packages})}**\n"
        f"- findings: **{len(findings)}**"
    )
    out.append("")
    out.append("| severity | count |")
    out.append("| --- | --- |")
    for s in ("critical", "high", "medium", "low", "info"):
        out.append(f"| {s} | {counts.get(s, 0)} |")
    out.append("")

    if result.skipped:
        out.append("**Skipped:** " + ", ".join(result.skipped))
        out.append("")

    if not findings:
        out.append("No findings.")
        return "\n".join(out)

    out.append("## Findings")
    out.append("")
    for f in findings:
        out.append(f"### {f.package.key} — {f.title}")
        out.append("")
        out.append(
            f"- **severity:** {f.severity.label}  ·  **score:** {f.score}  ·  "
            f"**rule:** `{f.rule_id}`"
        )
        if f.package.location:
            out.append(f"- **location:** `{f.package.location}`")
        out.append("")
        if f.description:
            out.append(f.description)
            out.append("")
        if f.evidence:
            out.append("**Evidence**")
            out.append("")
            for ev in f.evidence:
                bullet = f"- `{ev.kind}`: {ev.summary}"
                if ev.location:
                    bullet += f" — `{ev.location}`"
                if ev.url:
                    bullet += f" ([source]({ev.url}))"
                out.append(bullet)
            out.append("")
        if f.references:
            out.append("**References**")
            out.append("")
            for r in f.references:
                out.append(f"- {r}")
            out.append("")
    return "\n".join(out)


def render_json(result: ScanResult) -> str:
    def to_jsonable(obj):
        if is_dataclass(obj):
            return {k: to_jsonable(v) for k, v in asdict(obj).items()}
        if isinstance(obj, Severity):
            return obj.label
        if isinstance(obj, datetime):
            return obj.isoformat() + "Z"
        if isinstance(obj, dict):
            return {k: to_jsonable(v) for k, v in obj.items()}
        if isinstance(obj, list | tuple):
            return [to_jsonable(v) for v in obj]
        if hasattr(obj, "__fspath__"):
            return str(obj)
        return obj

    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "packages": [to_jsonable(p) for p in result.packages],
        "findings": [to_jsonable(f) for f in result.findings],
        "skipped": result.skipped,
    }
    return json.dumps(payload, indent=2, default=str)


def render_html(result: ScanResult) -> str:
    md = render_markdown(result)
    body = (
        md.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>snitch report</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:960px;margin:2em auto;"
        "padding:0 1em;line-height:1.5;color:#222}pre{background:#f6f8fa;padding:1em;"
        "border-radius:6px;overflow:auto}code{background:#f6f8fa;padding:0.1em 0.3em;"
        "border-radius:3px}</style></head><body><pre>"
        f"{body}"
        "</pre></body></html>"
    )


def write_findings_list(findings: Iterable[Finding]) -> list[dict]:
    out = []
    for f in findings:
        out.append(
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.label,
                "score": f.score,
                "package": f.package.key,
                "evidence": [ev.summary for ev in f.evidence],
            }
        )
    return out
