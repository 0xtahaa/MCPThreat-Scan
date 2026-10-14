"""Scan wizard: select a path, set options, run the scan in the background."""

from __future__ import annotations

from functools import partial
from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Button, Checkbox, DirectoryTree, Footer, Header, Input, Static

from mcpthreat_scan.core.orchestrator import run_scan
from mcpthreat_scan.tui.screens.running import RunningScreen


class ScanPathScreen(Screen):
    """First step: type a path OR select it via a tree.

    The tree alone cannot go "up" beyond its start root or switch to another drive
    (Textual limitation of DirectoryTree) - hence an additional input field for any
    absolute path (e.g. from a drive other than the one the scanner itself is on).
    """

    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("s", "select_path", "Select highlighted entry"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            "Type/paste the path to the MCP server and press Enter - OR navigate the "
            "tree below and select the highlighted entry with 's' (file OR folder).",
            id="hint",
        )
        yield Input(placeholder=r"e.g. C:\Projects\my-mcp-server", id="path-input")
        yield DirectoryTree(str(Path.home()), id="path-tree")
        yield Footer()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_select_path(self) -> None:
        tree = self.query_one(DirectoryTree)
        node = tree.cursor_node
        if node is None or node.data is None:
            return
        self.app.push_screen(ScanOptionsScreen(node.data.path))

    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        self.app.push_screen(ScanOptionsScreen(event.path))

    def on_input_submitted(self, event: Input.Submitted) -> None:
        value = event.value.strip()
        if not value:
            return
        path = Path(value).expanduser()
        if not path.exists():
            self.notify(f"Path not found: {path}", severity="error")
            return
        self.app.push_screen(ScanOptionsScreen(path))


class ScanOptionsScreen(Screen):
    """Second step: confirm the selected path, explain options in plain words."""

    BINDINGS = [Binding("escape", "back", "Back")]

    def __init__(self, target_path: Path) -> None:
        super().__init__()
        self._target_path = target_path

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="options"):
            yield Static(f"Target: {self._target_path}")
            yield Checkbox(
                "Additional AI review for suspicious tool descriptions "
                "(needs a valid OpenAI API key, costs a small amount "
                "per candidate - without this option only the free "
                "basic check runs)",
                id="ai-review",
            )
            yield Button("Start scan", id="start", variant="primary")
        yield Footer()

    def action_back(self) -> None:
        self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "start":
            return
        ai_review = self.query_one("#ai-review", Checkbox).value
        task = partial(run_scan, self._target_path, ai_review=ai_review)
        self.app.push_screen(RunningScreen(task, f"Scanning {self._target_path} ..."))
