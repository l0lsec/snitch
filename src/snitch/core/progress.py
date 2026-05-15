"""Progress reporting primitives used by the orchestrator.

The orchestrator drives a `ProgressReporter` through phases; concrete
implementations decide whether to render a live Rich bar, print one-line
phase markers (for non-TTY contexts), or stay silent.
"""

from __future__ import annotations

from typing import Protocol

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)


class ProgressReporter(Protocol):
    """Protocol the orchestrator calls to publish progress events."""

    def start_phase(self, name: str, total: int | None = None) -> None: ...

    def update(self, label: str | None = None, advance: int = 1) -> None: ...

    def end_phase(self) -> None: ...

    def note(self, msg: str) -> None: ...


class NullReporter:
    """Reporter that swallows every event. Used as the default."""

    def start_phase(self, name: str, total: int | None = None) -> None:
        return None

    def update(self, label: str | None = None, advance: int = 1) -> None:
        return None

    def end_phase(self) -> None:
        return None

    def note(self, msg: str) -> None:
        return None

    def __enter__(self) -> "NullReporter":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


class _PlainReporter:
    """One-line-per-phase reporter for non-TTY / CI output."""

    def __init__(self, console: Console) -> None:
        self._console = console
        self._phase: str | None = None
        self._count = 0
        self._total: int | None = None

    def start_phase(self, name: str, total: int | None = None) -> None:
        self._phase = name
        self._count = 0
        self._total = total
        suffix = f" (0/{total})" if total else ""
        self._console.print(f"[dim]» {name}{suffix}[/dim]")

    def update(self, label: str | None = None, advance: int = 1) -> None:
        self._count += advance

    def end_phase(self) -> None:
        if self._phase is None:
            return
        if self._total:
            self._console.print(
                f"[dim]✓ {self._phase} ({self._count}/{self._total})[/dim]"
            )
        else:
            self._console.print(f"[dim]✓ {self._phase} ({self._count})[/dim]")
        self._phase = None
        self._count = 0
        self._total = None

    def note(self, msg: str) -> None:
        self._console.print(f"[dim]  {msg}[/dim]")

    def __enter__(self) -> "_PlainReporter":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


class RichProgressReporter:
    """Live Rich progress display with bar + ETA per phase.

    Falls back to a quiet one-line-per-phase printer when the attached
    console isn't a TTY (e.g. when output is piped or redirected).
    """

    def __init__(self, console: Console, *, on_note=None) -> None:
        self._console = console
        self._on_note = on_note
        self._fallback: _PlainReporter | None = None
        self._progress: Progress | None = None
        self._task_id = None
        self._phase: str | None = None

    def __enter__(self) -> "RichProgressReporter":
        if not self._console.is_terminal:
            self._fallback = _PlainReporter(self._console)
            self._fallback.__enter__()
            return self
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.fields[phase]}[/bold] {task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TextColumn("eta"),
            TimeRemainingColumn(),
            console=self._console,
            transient=True,
        )
        self._progress.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._fallback is not None:
            self._fallback.__exit__(exc_type, exc, tb)
            self._fallback = None
            return None
        if self._progress is not None:
            self._progress.stop()
            self._progress = None
        return None

    def start_phase(self, name: str, total: int | None = None) -> None:
        if self._fallback is not None:
            self._fallback.start_phase(name, total)
            return
        if self._progress is None:
            return
        if self._task_id is not None:
            self._progress.remove_task(self._task_id)
            self._task_id = None
        self._phase = name
        self._task_id = self._progress.add_task(
            description="",
            total=total,
            phase=name,
        )

    def update(self, label: str | None = None, advance: int = 1) -> None:
        if self._fallback is not None:
            self._fallback.update(label, advance)
            return
        if self._progress is None or self._task_id is None:
            return
        kwargs = {"advance": advance}
        if label is not None:
            kwargs["description"] = label
        self._progress.update(self._task_id, **kwargs)

    def end_phase(self) -> None:
        if self._fallback is not None:
            self._fallback.end_phase()
            return
        if self._progress is None or self._task_id is None:
            return
        self._progress.remove_task(self._task_id)
        self._task_id = None
        self._phase = None

    def note(self, msg: str) -> None:
        if self._on_note is not None:
            try:
                self._on_note(msg)
            except Exception:
                pass
        if self._fallback is not None:
            self._fallback.note(msg)
            return
        if self._progress is not None:
            self._progress.console.log(f"[dim]{msg}[/dim]")
        else:
            self._console.log(f"[dim]{msg}[/dim]")


__all__ = [
    "NullReporter",
    "ProgressReporter",
    "RichProgressReporter",
]
