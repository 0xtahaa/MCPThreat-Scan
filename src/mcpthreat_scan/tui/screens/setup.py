"""Setup help: set OPENAI_API_KEY without a user having to create a .env file by hand."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable

from dotenv import set_key
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Static

_ENV_PATH = Path(".env")


class SetupScreen(Screen):
    """Shown on first start when no OPENAI_API_KEY was found."""

    def __init__(self, on_done: Callable[[], None]) -> None:
        super().__init__()
        self._on_done = on_done

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="setup"):
            yield Static(
                "No OpenAI API key found. This key is only needed for the OPTIONAL "
                "additional AI review of suspicious tool descriptions - "
                "scanning and comparing work without it. The key is never "
                "displayed or logged, only stored locally in a .env file."
            )
            yield Input(placeholder="sk-...", password=True, id="key-input")
            yield Button("Save", id="save", variant="primary")
            yield Button("Skip", id="skip")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "skip":
            self._on_done()
            return

        value = self.query_one("#key-input", Input).value.strip()
        if not value:
            self.notify("No key entered - skipped.", severity="warning")
            self._on_done()
            return

        set_key(str(_ENV_PATH), "OPENAI_API_KEY", value)
        os.environ["OPENAI_API_KEY"] = value
        self.notify("API key saved.")
        self._on_done()
