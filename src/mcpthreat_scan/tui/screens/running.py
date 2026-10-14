"""Progress screen: runs a scanner function in the background without freezing the UI."""

from __future__ import annotations

from typing import Callable

from textual import work
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Footer, LoadingIndicator, Static

from mcpthreat_scan.core.exceptions import ReportError


class RunningScreen(Screen):
    """Show a loading indicator while `task()` runs in a worker thread.

    Deliberately WITHOUT Header(): this screen is only a short intermediate display that,
    depending on the duration of the real scanner function (Semgrep subprocess etc.), is
    dismissed very quickly (pop_screen() in _on_success/_on_error). A Header() here
    introduced a rare Textual-internal timing problem during fast mounting/unmounting
    in practice (see tests/test_tui.py) - omitting it entirely is simpler and more robust
    than pausing the race away.
    """

    def __init__(self, task: Callable[[], dict], status_text: str) -> None:
        super().__init__()
        # Do not call this "self._task": Textual's own Screen base class (MessagePump)
        # already uses an attribute named "_task" internally (its own asyncio task) -
        # an assignment of the same name here is silently overwritten by Textual.
        self._work_fn = task
        self._status_text = status_text

    def compose(self) -> ComposeResult:
        yield Static(self._status_text, id="status")
        yield LoadingIndicator()
        yield Footer()

    def on_mount(self) -> None:
        self._run_task()

    @work(thread=True)
    def _run_task(self) -> None:
        # Runs in a background thread (Semgrep/pip-audit/OpenAI calls would otherwise block
        # the whole interface). UI updates must go through call_from_thread.
        try:
            report = self._work_fn()
        except ReportError as exc:
            self.app.call_from_thread(self._on_error, str(exc))
            return
        self.app.call_from_thread(self._on_success, report)

    def _on_success(self, report: dict) -> None:
        from mcpthreat_scan.tui.screens.results import ResultsScreen

        self.app.pop_screen()
        self.app.push_screen(ResultsScreen(report))

    def _on_error(self, message: str) -> None:
        self.app.pop_screen()
        self.notify(message, severity="error", timeout=10)
