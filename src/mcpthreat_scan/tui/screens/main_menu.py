"""Main menu screen: entry point to all wizards/views."""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Footer, Header, OptionList, Static
from textual.widgets.option_list import Option

from mcpthreat_scan.tui.banner import render_ascii_logo, render_info_line
from mcpthreat_scan.tui.screens.diff_wizard import open_diff_wizard
from mcpthreat_scan.tui.screens.ignore_manager import IgnoreManagerScreen
from mcpthreat_scan.tui.screens.reputation_manager import ReputationManagerScreen
from mcpthreat_scan.tui.screens.scan_wizard import ScanPathScreen
from mcpthreat_scan.tui.theme import ACCENT

_MENU_ITEMS = [
    ("scan", "Start scan"),
    ("diff", "Compare versions (diff)"),
    ("ignore", "Manage ignore list"),
    ("reputation", "Manage trusted servers"),
    ("quit", "Quit"),
]


class MainMenuScreen(Screen):
    """First screen after startup (or after the setup help)."""

    BINDINGS = [Binding("q", "quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(Text(render_ascii_logo(), style=f"bold {ACCENT}"), id="logo")
        yield Static(render_info_line(), id="banner-info")
        yield OptionList(*(Option(label, id=key) for key, label in _MENU_ITEMS))
        yield Footer()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_id == "quit":
            self.app.exit()
        elif event.option_id == "scan":
            self.app.push_screen(ScanPathScreen())
        elif event.option_id == "diff":
            open_diff_wizard(self.app)
        elif event.option_id == "ignore":
            self.app.push_screen(IgnoreManagerScreen())
        elif event.option_id == "reputation":
            self.app.push_screen(ReputationManagerScreen())

    def action_quit(self) -> None:
        self.app.exit()
