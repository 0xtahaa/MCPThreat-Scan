"""Interactive TUI: entry point that wires the setup help and the main menu."""

from __future__ import annotations

import os

from dotenv import load_dotenv
from textual.app import App

from mcpthreat_scan.tui.screens.main_menu import MainMenuScreen
from mcpthreat_scan.tui.screens.setup import SetupScreen
from mcpthreat_scan.tui.theme import MCP_SCANNER_THEME


class MCPScannerApp(App):
    """MCPThreat-Scan - interactive terminal interface."""

    TITLE = "MCPThreat-Scan"
    SUB_TITLE = "Zero-Execution Static Analysis"
    CSS_PATH = "app.tcss"
    BINDINGS = [("q", "quit", "Quit")]

    def on_mount(self) -> None:
        self.register_theme(MCP_SCANNER_THEME)
        self.theme = "mcp-scanner"
        load_dotenv()
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
