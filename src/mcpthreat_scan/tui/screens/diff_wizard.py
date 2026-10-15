"""Version comparison wizard: pick the baseline, then the current version (two files or two folders)."""

from __future__ import annotations

from functools import partial
from pathlib import Path
from typing import Callable

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import DirectoryTree, Footer, Header, Input, Static

from mcpthreat_scan.core.orchestrator import run_version_comparison
from mcpthreat_scan.tui.screens.running import RunningScreen
from mcpthreat_scan.tui.theme import SEVERITY_COLORS


class DiffPathScreen(Screen):
    """Selects a file or folder - reused for the baseline and the current version.

    Input field in addition to the tree, for the same reason as in scan_wizard.py: the tree
    cannot go above its start root or switch to another drive.
    """

    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("s", "select_path", "Select highlighted entry"),
    ]

    def __init__(
        self, step_label: str, on_chosen: Callable[[Path], None], *, expect_dir: bool | None = None
    ) -> None:
        super().__init__()
        self._step_label = step_label
        self._on_chosen = on_chosen
        # None: file or folder; True/False: must match the baseline (two files or two folders).
        self._expect_dir = expect_dir

    def compose(self) -> ComposeResult:
        kind = {None: "a file or a folder", True: "a folder", False: "a file"}[self._expect_dir]
        yield Header()
        yield Static(self._step_label, classes="step-title")
        yield Static(
            f"Type or paste the path of {kind} and press Enter, OR select the highlighted entry "
            "in the tree with 's'. Both versions must be two files or two folders.",
            id="hint",
        )
        yield Input(placeholder=r"e.g. C:\Projects\my-mcp-server", id="path-input")
        yield Static("", id="path-status")
        yield DirectoryTree(str(Path.home()), id="path-tree")
        yield Footer()

    def action_back(self) -> None:
        self.app.pop_screen()

    def _choose(self, path: Path) -> None:
        error = None
        if not path.exists():
            error = f"Path not found: {path}"
        elif self._expect_dir is not None and path.is_dir() != self._expect_dir:
            error = "The baseline is a folder - pick a folder." if self._expect_dir else \
                "The baseline is a file - pick a file."
        if error:
            self.query_one("#path-status", Static).update(Text(error, style=SEVERITY_COLORS["ERROR"]))
            self.notify(error, severity="error")
            return
        self._on_chosen(path)

    def action_select_path(self) -> None:
        node = self.query_one(DirectoryTree).cursor_node
        if node is None or node.data is None:
            return
        self._choose(node.data.path)

    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        self._choose(event.path)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        value = event.value.strip()
        if not value:
            return
        self._choose(Path(value).expanduser())


def open_diff_wizard(app: App) -> None:
    """Start the two-step wizard (baseline, then current version), then run the comparison."""

    def after_baseline_chosen(before_path: Path) -> None:
        def after_current_chosen(after_path: Path) -> None:
            task = partial(run_version_comparison, before_path, after_path)
            app.pop_screen()
            app.push_screen(
                RunningScreen(
                    task,
                    f"Comparing {before_path.name} -> {after_path.name} ...",
                    kind="compare",
                    target=f"{before_path} -> {after_path}",
                )
            )

        app.pop_screen()
        app.push_screen(
            DiffPathScreen(
                "Step 2 of 4 · Select current version (newer)",
                after_current_chosen,
                expect_dir=before_path.is_dir(),
            )
        )

    app.push_screen(DiffPathScreen("Step 1 of 4 · Select baseline (older version)", after_baseline_chosen))
