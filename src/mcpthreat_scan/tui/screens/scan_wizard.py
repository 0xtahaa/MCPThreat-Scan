"""Scan wizard: select and validate a target, confirm options, run the scan in the background."""

from __future__ import annotations

import os
from functools import partial
from pathlib import Path

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Button, Checkbox, DirectoryTree, Footer, Header, Input, Static

from mcpthreat_scan.core.orchestrator import count_source_files, run_scan
from mcpthreat_scan.tui.display import labeled
from mcpthreat_scan.tui.screens.running import RunningScreen
from mcpthreat_scan.tui.state import set_target
from mcpthreat_scan.tui.theme import ACCENT, SEVERITY_COLORS, TEXT_MUTED


def validate_target(path: Path) -> tuple[str | None, int]:
    """(error message or None, number of source files in scope) for a scan target.

    Only looks at the file system; nothing in the target is run."""
    if not path.exists():
        return f"Path not found: {path}", 0
    if not (path.is_dir() or path.is_file()):
        return f"Not a file or folder: {path}", 0
    count = count_source_files(path)
    if count == 0:
        if path.is_file():
            return "Unsupported file type: the scanner reads .py, .ts, .tsx, .js, .jsx, .mjs and .cjs files.", 0
        return "No Python or TypeScript/JavaScript source files found in this folder.", 0
    return None, count


class ScanPathScreen(Screen):
    """First step: type a path OR select it via a tree.

    The tree alone cannot go "up" beyond its start root or switch to another drive
    (Textual limitation of DirectoryTree) - hence an additional input field for any
    absolute path (e.g. from a drive other than the one the scanner itself is on).
    """

    WIZARD_STEP = True  # the summary screen removes these when it returns to the menu

    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("s", "select_path", "Select highlighted entry"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Step 1 of 3 · Select target", classes="step-title")
        yield Static(
            "Type or paste the path of an MCP server (folder or source file) and press Enter - OR "
            "navigate the tree below and select the highlighted entry with 's'.",
            id="hint",
        )
        yield Input(placeholder=r"e.g. C:\Projects\my-mcp-server", id="path-input")
        yield Static("The target is only read, never executed.", id="path-status")
        yield DirectoryTree(str(Path.home()), id="path-tree")
        yield Footer()

    def action_back(self) -> None:
        self.app.pop_screen()

    def _choose(self, path: Path) -> None:
        """Validate the target before the next step; show why it is not accepted."""
        error, count = validate_target(path)
        status = self.query_one("#path-status", Static)
        if error:
            status.update(Text(error, style=SEVERITY_COLORS["ERROR"]))
            self.notify(error, severity="error")
            return
        set_target(self.app, path)
        self.app.push_screen(ScanOptionsScreen(path, files_in_scope=count))

    def action_select_path(self) -> None:
        tree = self.query_one(DirectoryTree)
        node = tree.cursor_node
        if node is None or node.data is None:
            return
        self._choose(node.data.path)

    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        self._choose(event.path)

    def on_input_changed(self, event: Input.Changed) -> None:
        # Cheap hint while typing; the full check (counting files) runs on Enter.
        value = event.value.strip()
        status = self.query_one("#path-status", Static)
        if not value:
            status.update("The target is only read, never executed.")
        elif Path(value).expanduser().exists():
            status.update(Text("Press Enter to check this target.", style=ACCENT))
        else:
            status.update(Text("Path not found yet.", style=SEVERITY_COLORS["WARNING"]))

    def on_input_submitted(self, event: Input.Submitted) -> None:
        value = event.value.strip()
        if not value:
            return
        self._choose(Path(value).expanduser())


class ScanOptionsScreen(Screen):
    """Confirm the validated target, explain options in plain words, start the scan."""

    AUTO_FOCUS = "#start"
    WIZARD_STEP = True  # the summary screen removes these when it returns to the menu

    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("a", "toggle_ai", "Toggle AI review"),
    ]

    def __init__(self, target_path: Path, *, files_in_scope: int | None = None) -> None:
        super().__init__()
        self._target_path = target_path
        self._files_in_scope = (
            files_in_scope if files_in_scope is not None else count_source_files(target_path)
        )

    def compose(self) -> ComposeResult:
        kind = "folder" if self._target_path.is_dir() else "file"
        has_key = bool(os.environ.get("OPENAI_API_KEY"))
        yield Header()
        yield Static("Step 1 of 3 · Confirm target and start", classes="step-title")
        with Vertical(id="options"):
            details = labeled("Target", str(self._target_path))
            details.append("\n")
            details.append_text(labeled("Type", kind))
            details.append("\n")
            details.append_text(labeled("Files in scope", f"{self._files_in_scope} source file(s)"))
            details.append("\n")
            details.append_text(labeled("Mode", "static analysis, the target is never executed"))
            yield Static(details, id="target-details")
            yield Checkbox("Additional AI review of suspicious tool descriptions", id="ai-review")
            yield Static(
                Text("Needs a valid OpenAI API key and costs a small amount per candidate. "
                     "Without it only the free basic check runs.", style=TEXT_MUTED),
                id="ai-note",
            )
            if not has_key:
                yield Static(Text("No OpenAI API key is configured; the AI review will be skipped "
                                  "with a note on each candidate.", style=SEVERITY_COLORS["WARNING"]))
            yield Button("Start scan", id="start", variant="primary")
        yield Footer()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_toggle_ai(self) -> None:
        checkbox = self.query_one("#ai-review", Checkbox)
        checkbox.value = not checkbox.value

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "start":
            return
        ai_review = self.query_one("#ai-review", Checkbox).value
        task = partial(run_scan, self._target_path, ai_review=ai_review)
        self.app.push_screen(
            RunningScreen(
                task,
                f"Scanning {self._target_path} ...",
                kind="scan",
                target=str(self._target_path),
                ai_review=ai_review,
                files_in_scope=self._files_in_scope,
            )
        )
