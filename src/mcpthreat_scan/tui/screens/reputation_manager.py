"""Reputation manager: shows trusted servers, trust can be revoked per entry.

Reads and revokes entries through the policy layer (list_reviewed/revoke_review); the
screen knows neither the storage path nor the JSON format of the reputation store.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

from mcpthreat_scan.policy.reputation import list_reviewed, revoke_review


class ReputationManagerScreen(Screen):
    """Show all servers marked as trusted from the reputation store."""

    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("d", "revoke_selected", "Revoke trust"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            "Servers that have already been reviewed successfully. 'd' revokes the "
            "trust for the highlighted entry.",
            id="hint",
        )
        yield DataTable(id="reputation-table")
        yield Footer()

    def on_mount(self) -> None:
        self._reload()

    def _reload(self) -> None:
        table = self.query_one(DataTable)
        table.clear(columns=True)
        table.add_columns("Server", "Last reviewed")
        table.cursor_type = "row"
        for name, entry in sorted(list_reviewed().items()):
            table.add_row(name, entry.get("reviewed_at", "-"), key=name)

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_revoke_selected(self) -> None:
        table = self.query_one(DataTable)
        if table.row_count == 0 or table.cursor_row is None:
            return

        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        name = row_key.value

        revoke_review(name)

        self.notify(f"Trust revoked: {name}")
        self._reload()
