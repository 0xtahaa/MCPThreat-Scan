"""Diff wizard: select and compare two file versions (before/after)."""

from __future__ import annotations

from functools import partial
from pathlib import Path
from typing import Callable

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import DirectoryTree, Footer, Header, Input, Static

from mcpthreat_scan.core.orchestrator import run_diff
from mcpthreat_scan.tui.screens.running import RunningScreen


class DiffPathScreen(Screen):
    """Selects a single file - reused for 'before' and 'after'.

    Input field in addition to the tree, for the same reason as in scan_wizard.py: the tree
    cannot go above its start root or switch to another drive.
    """

    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("s", "select_path", "Select this file"),
    ]

    def __init__(self, step_label: str, on_chosen: Callable[[Path], None]) -> None:
        super().__init__()
        self._step_label = step_label
        self._on_chosen = on_chosen

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            f"{self._step_label}. Type/paste a path and press Enter, OR select the "
            "highlighted file in the tree with 's'.",
            id="hint",
        )
        yield Input(placeholder=r"e.g. C:\Projects\my-mcp-server\server.py", id="path-input")
        yield DirectoryTree(str(Path.home()), id="path-tree")
        yield Footer()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_select_path(self) -> None:
        tree = self.query_one(DirectoryTree)
        node = tree.cursor_node
        if node is None or node.data is None or node.data.path.is_dir():
            return
        self._on_chosen(node.data.path)

    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        self._on_chosen(event.path)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        value = event.value.strip()
        if not value:
            return
        path = Path(value).expanduser()
        if not path.is_file():
            self.notify(f"File not found: {path}", severity="error")
            return
        self._on_chosen(path)


def open_diff_wizard(app: App) -> None:
    """Start the two-step diff wizard (before file, then after file)."""

    def after_before_chosen(before_path: Path) -> None:
        def after_after_chosen(after_path: Path) -> None:
            task = partial(run_diff, before_path, after_path)
            app.pop_screen()
            app.push_screen(
                RunningScreen(task, f"Comparing {before_path.name} -> {after_path.name} ...")
            )

        app.pop_screen()
        app.push_screen(DiffPathScreen("After version (new file)", after_after_chosen))

    app.push_screen(DiffPathScreen("Before version (old file)", after_before_chosen))
