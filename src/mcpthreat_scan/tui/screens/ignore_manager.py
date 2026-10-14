"""Ignore manager: shows and manages entries from .mcpscannerignore."""

from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

from mcpthreat_scan.policy.ignore import load_ignore_rules, remove_ignore_rule


class IgnoreManagerScreen(Screen):
    """Show all suppressed (file, category) entries, removable with a key."""

    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("d", "remove_selected", "Remove entry"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            "These findings are suppressed during scans. 'd' removes the highlighted entry.",
            id="hint",
        )
        yield DataTable(id="ignore-table")
        yield Footer()

    def on_mount(self) -> None:
        self._reload()

    def _reload(self) -> None:
        table = self.query_one(DataTable)
        table.clear(columns=True)
        table.add_columns("File", "Category")
        table.cursor_type = "row"
        rules = sorted(load_ignore_rules())
        for file_part, category_part in rules:
            table.add_row(file_part, category_part, key=f"{file_part}:{category_part}")

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_remove_selected(self) -> None:
        table = self.query_one(DataTable)
        if table.row_count == 0 or table.cursor_row is None:
            return

        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        # rsplit instead of split: Windows paths like "C:\..." contain a colon themselves.
        file_part, category_part = row_key.value.rsplit(":", 1)

        remove_ignore_rule(file_part, category_part)

        self.notify(f"Removed: {category_part} in {Path(file_part).name}")
        self._reload()
