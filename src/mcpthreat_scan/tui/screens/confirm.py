"""Confirmation dialog for changes that hide findings or remove stored entries."""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static


class ConfirmScreen(ModalScreen):
    """Ask "really?" and dismiss with True/False. Cancel has the focus, so a stray Enter is safe."""

    AUTO_FOCUS = "#cancel"

    BINDINGS = [
        Binding("y", "confirm", "Yes"),
        Binding("n", "cancel", "No"),
        Binding("escape", "cancel", "Cancel"),
    ]

    def __init__(self, title: str, detail: str = "", *, confirm_label: str = "Confirm") -> None:
        super().__init__()
        self._title = title
        self._detail = detail
        self._confirm_label = confirm_label

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Static(Text(self._title, style="bold"), classes="dialog-title")
            if self._detail:
                yield Static(Text(self._detail), classes="dialog-detail")
            with Horizontal(classes="dialog-buttons"):
                yield Button(self._confirm_label, id="confirm", variant="error")
                yield Button("Cancel", id="cancel")
            yield Static(Text("y = confirm · n / Esc = cancel"), classes="dialog-hint")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "confirm")

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)
