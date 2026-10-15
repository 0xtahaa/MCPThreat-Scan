"""Main menu screen: header, workspace status and the six top-level actions."""

from __future__ import annotations

import os

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import OptionList, Static
from textual.widgets.option_list import Option

from mcpthreat_scan.tui.banner import render_header, render_wordmark, wordmark_width
from mcpthreat_scan.tui.screens.diff_wizard import open_diff_wizard
from mcpthreat_scan.tui.display import shorten_left
from mcpthreat_scan.tui.logo import render_logo
from mcpthreat_scan.tui.screens.results import ResultsScreen
from mcpthreat_scan.tui.screens.scan_wizard import ScanPathScreen
from mcpthreat_scan.tui.screens.settings import SettingsScreen
from mcpthreat_scan.tui.screens.trust import TrustScreen
from mcpthreat_scan.tui.theme import TEXT_MUTED

_MENU_ITEMS = [
    ("scan", "Start New Scan"),
    ("diff", "Compare Versions (Diff)"),
    ("findings", "View Findings"),
    ("trust", "Trusted Servers & Exclusions"),
    ("settings", "Settings & Help"),
    ("quit", "Quit"),
]

# Must stay in sync with BINDINGS below (tests/test_tui_menu_navigation.py checks it).
SHORTCUTS_LINE = "↑↓ Navigate · Enter Select · S Scan · D Diff · ? Help · Q Quit"


_LABEL_WIDTH = 10
_MARK_WIDTH = 9  # the 8-column mark plus one column of space


def _workspace_text(app: App, value_width: int = 0) -> Text:
    """Workspace rows from the real app state; empty state is shown as such, never invented."""
    run, report = app.last_run, app.last_report
    ai_note = "available (opt-in per scan)" if os.environ.get("OPENAI_API_KEY") else "not configured"
    finished = run.get("finished_at") if run else None
    target = str(app.current_target) if app.current_target else "none selected"
    rows = [
        ("Target", shorten_left(target, value_width)),
        ("Last run", f"{run['kind']} {run['status']}" if run else "none yet"),
        ("Finished", finished.strftime("%Y-%m-%d %H:%M") if finished else "-"),
        ("Mode", f"static, zero-execution · AI review {ai_note}"),
        ("Results", f"{len(report['findings'])} finding(s) available" if report else "none (run a scan first)"),
    ]
    text = Text()
    for index, (label, value) in enumerate(rows):
        if index:
            text.append("\n")
        text.append(f"{label:<{_LABEL_WIDTH}}", style=TEXT_MUTED)
        text.append(value)
    return text


class MainMenuScreen(Screen):
    """First screen after startup (or after the setup help)."""

    AUTO_FOCUS = "#main-menu"

    BINDINGS = [
        Binding("s", "scan", "Scan", show=False),
        Binding("d", "diff", "Diff", show=False),
        Binding("question_mark", "help", "Help", show=False),
        Binding("q", "quit", "Quit", show=False),
    ]

    def compose(self) -> ComposeResult:
        with Horizontal(id="brand"):
            yield Static(render_logo(), id="brand-mark")
            yield Static(render_wordmark(), id="wordmark")
            yield Static(render_header(), id="app-header")
        with VerticalScroll(id="menu-body"):
            yield Static("WORKSPACE", classes="section-title")
            yield Static(id="workspace")
            yield Static("ACTIONS", classes="section-title")
            yield OptionList(*(Option(label, id=key) for key, label in _MENU_ITEMS), id="main-menu")
        yield Static(SHORTCUTS_LINE, id="shortcuts")

    def on_mount(self) -> None:
        self._refresh()

    def on_screen_resume(self) -> None:
        # Coming back from a scan/diff/findings screen: show the new state.
        self._refresh()

    def on_resize(self) -> None:
        self._layout_brand()
        self._refresh()

    def _layout_brand(self) -> None:
        """Pick the widest header that fits: mark + wordmark, wordmark alone, or mark + compact text."""
        width = self.query_one("#brand").size.width
        if not width:
            return
        with_mark = width >= _MARK_WIDTH + wordmark_width()
        wordmark = width >= wordmark_width()
        self.query_one("#brand-mark").display = with_mark or not wordmark
        self.query_one("#wordmark").display = wordmark
        self.query_one("#app-header").display = not wordmark

    def _refresh(self) -> None:
        workspace = self.query_one("#workspace", Static)
        workspace.update(_workspace_text(self.app, max(workspace.size.width - _LABEL_WIDTH, 0)))
        menu = self.query_one(OptionList)
        if self.app.last_report is None:
            menu.disable_option("findings")
        else:
            menu.enable_option("findings")

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self._open(event.option_id)

    def _open(self, key: str) -> None:
        if key == "quit":
            self.app.exit()
        elif key == "scan":
            self.app.push_screen(ScanPathScreen())
        elif key == "diff":
            open_diff_wizard(self.app)
        elif key == "findings":
            self.app.push_screen(ResultsScreen(self.app.last_report))
        elif key == "trust":
            self.app.push_screen(TrustScreen())
        elif key == "settings":
            self.app.push_screen(SettingsScreen())

    def action_scan(self) -> None:
        self._open("scan")

    def action_diff(self) -> None:
        self._open("diff")

    def action_help(self) -> None:
        self._open("settings")

    def action_quit(self) -> None:
        self.app.exit()
