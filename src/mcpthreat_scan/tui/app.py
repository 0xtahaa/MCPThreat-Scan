"""Interactive TUI: entry point that wires the setup help and the main menu."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import find_dotenv, load_dotenv
from textual.app import App

from mcpthreat_scan.tui.screens.main_menu import MainMenuScreen
from mcpthreat_scan.tui.screens.setup import SetupScreen
from mcpthreat_scan.tui.theme import MCP_SCANNER_THEME


class MCPScannerApp(App):
    """MCPThreat-Scan - interactive terminal interface."""

    TITLE = "Autorea MCP Threat Scan"
    SUB_TITLE = "Zero-Execution Static Analysis"
    CSS_PATH = "app.tcss"
    ENABLE_COMMAND_PALETTE = False
    BINDINGS = [("q", "quit", "Quit")]

    def __init__(self) -> None:
        super().__init__()
        # Workspace state shown on the main menu. Plain attributes, filled by the scan/diff
        # screens from real results only; None means "nothing has happened yet".
        self.current_target: Path | None = None
        self.last_run: dict | None = None  # kind, target, status, finished_at, duration_s, ai_review, error
        self.last_report: dict | None = None  # report of the last completed run

    def on_mount(self) -> None:
        self.register_theme(MCP_SCANNER_THEME)
        self.theme = "mcp-scanner"
        load_dotenv(find_dotenv(usecwd=True))
        if os.environ.get("OPENAI_API_KEY"):
            self.push_screen(MainMenuScreen())
        else:
            self.push_screen(SetupScreen(self._show_main_menu))

    def _show_main_menu(self) -> None:
        self.pop_screen()
        self.push_screen(MainMenuScreen())


def run() -> None:
    MCPScannerApp().run()


if __name__ == "__main__":
    run()
