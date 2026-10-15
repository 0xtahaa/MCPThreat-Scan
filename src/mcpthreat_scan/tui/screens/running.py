"""Progress screen: runs a scanner function in the background without freezing the UI.

Shows only what the engine really reports: the current phase (progress callback of the
orchestrator), the phases finished so far, elapsed time and, when known, the number of source
files in scope. There is no percentage - the engine does not know one."""

from __future__ import annotations

import inspect
import time
from typing import Callable

from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Footer, LoadingIndicator, Static

from mcpthreat_scan.core.exceptions import ReportError
from mcpthreat_scan.tui.display import format_duration, labeled, shorten_left
from mcpthreat_scan.tui.state import record_run
from mcpthreat_scan.tui.theme import ACCENT, TEXT_MUTED

_KIND_STEP = {"scan": "Step 2 of 3 · Scan progress", "compare": "Step 3 of 4 · Comparison progress"}


def _accepts_progress(task: Callable[..., dict]) -> bool:
    """True if the task takes a `progress` keyword (run_scan and run_version_comparison do)."""
    try:
        return "progress" in inspect.signature(task).parameters
    except (TypeError, ValueError):  # a callable without an inspectable signature
        return False


class RunningScreen(Screen):
    """Show progress while `task()` runs in a worker thread, then open the matching result screen.

    kind: "scan" -> scan summary, "compare" -> version comparison, anything else -> findings list.
    If `task` accepts a `progress` keyword it is called with a phase-name callback.

    Deliberately WITHOUT Header(): this screen is only a short intermediate display that,
    depending on the duration of the real scanner function (Semgrep subprocess etc.), is
    dismissed very quickly (pop_screen() in _on_success/_on_error). A Header() here
    introduced a rare Textual-internal timing problem during fast mounting/unmounting
    in practice (see tests/test_tui.py) - omitting it entirely is simpler and more robust
    than pausing the race away.
    """

    def __init__(
        self,
        task: Callable[..., dict],
        status_text: str,
        *,
        kind: str = "scan",
        target: str = "",
        ai_review: bool = False,
        files_in_scope: int | None = None,
    ) -> None:
        super().__init__()
        # Do not call this "self._task": Textual's own Screen base class (MessagePump)
        # already uses an attribute named "_task" internally (its own asyncio task) -
        # an assignment of the same name here is silently overwritten by Textual.
        self._work_fn = task
        self._status_text = status_text
        self._kind = kind
        self._target = target
        self._ai_review = ai_review
        self._files_in_scope = files_in_scope
        self._phases: list[str] = []
        self._started = time.monotonic()
        self._finished = False

    def compose(self) -> ComposeResult:
        yield Static(_KIND_STEP.get(self._kind, ""), id="step", classes="step-title")
        yield Static(self._status_text, id="status")
        yield Static(id="progress")
        yield LoadingIndicator()
        yield Static(
            "This run cannot be cancelled safely: the Semgrep stage is one external process.",
            id="cancel-note",
        )
        yield Footer()

    def on_mount(self) -> None:
        self._render_progress()
        self.set_interval(0.25, self._render_progress)
        self._run_task()

    def on_resize(self) -> None:
        self._render_progress()

    def _render_progress(self) -> None:
        if self._finished:
            return
        width = max(self.size.width - 20, 20)
        text = Text()
        if self._target:
            text.append_text(labeled("Target", shorten_left(self._target, width)))
            text.append("\n")
        text.append_text(labeled("Status", Text("Running", style=f"bold {ACCENT}")))
        text.append("\n")
        text.append_text(labeled("Phase", self._phases[-1] if self._phases else "Starting"))
        if self._files_in_scope is not None:
            text.append("\n")
            text.append_text(labeled("Files in scope", f"{self._files_in_scope} source file(s)"))
        text.append("\n")
        text.append_text(labeled("Elapsed", format_duration(time.monotonic() - self._started)))
        if len(self._phases) > 1:
            text.append("\n\n")
            for index, phase in enumerate(self._phases):
                done = index < len(self._phases) - 1
                text.append(("  ✓ " if done else "  › "), style=TEXT_MUTED if done else ACCENT)
                text.append(phase, style=TEXT_MUTED if done else "")
                if index < len(self._phases) - 1:
                    text.append("\n")
        self.query_one("#progress", Static).update(text)

    def _set_phase(self, phase: str) -> None:
        self._phases.append(phase)
        self._render_progress()

    def _report_phase(self, phase: str) -> None:
        # Called from the worker thread: UI updates must go through call_from_thread.
        try:
            self.app.call_from_thread(self._set_phase, phase)
        except RuntimeError:
            pass  # the app is shutting down; nobody is looking at the progress any more

    @work(thread=True)
    def _run_task(self) -> None:
        # Runs in a background thread (Semgrep/pip-audit/OpenAI calls would otherwise block
        # the whole interface). UI updates must go through call_from_thread.
        try:
            if _accepts_progress(self._work_fn):
                report = self._work_fn(progress=self._report_phase)
            else:
                report = self._work_fn()
        except ReportError as exc:
            self.app.call_from_thread(self._on_error, str(exc))
            return
        except Exception as exc:  # any unexpected scanner failure must not crash the whole UI
            self.app.call_from_thread(self._on_error, f"Unexpected error ({type(exc).__name__}): {exc}")
            return
        self.app.call_from_thread(self._on_success, report)

    def _on_success(self, report: dict) -> None:
        from mcpthreat_scan.tui.screens.comparison import ComparisonScreen
        from mcpthreat_scan.tui.screens.results import ResultsScreen
        from mcpthreat_scan.tui.screens.summary import ScanSummaryScreen

        self._finished = True
        duration = time.monotonic() - self._started
        record_run(
            self.app, self._kind, self._target, "completed",
            duration_s=duration, ai_review=self._ai_review, report=report,
        )
        self.app.pop_screen()
        if self._kind == "scan":
            self.app.push_screen(
                ScanSummaryScreen(report, duration_s=duration, ai_review=self._ai_review,
                                  files_in_scope=self._files_in_scope)
            )
        elif self._kind == "compare":
            self.app.push_screen(ComparisonScreen(report, duration_s=duration))
        else:
            self.app.push_screen(ResultsScreen(report))

    def _on_error(self, message: str) -> None:
        self._finished = True
        record_run(
            self.app, self._kind, self._target, "failed",
            duration_s=time.monotonic() - self._started, ai_review=self._ai_review, error=message,
        )
        self.app.pop_screen()
        self.notify(message, severity="error", timeout=10)
