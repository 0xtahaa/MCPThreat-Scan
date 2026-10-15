"""Export dialog: write the current report as JSON or SARIF.

The only TUI module (besides the API-key setup) that writes a file, and only the path the user
typed. The text comes from the same renderers as the CLI (--format json / sarif), so a report
exported here has the same schema as one printed by the command line."""

from __future__ import annotations

from pathlib import Path

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, OptionList, Static
from textual.widgets.option_list import Option

from mcpthreat_scan.reporting.json import render_json
from mcpthreat_scan.reporting.sarif import render_sarif
from mcpthreat_scan.tui.screens.confirm import ConfirmScreen
from mcpthreat_scan.tui.theme import SEVERITY_COLORS

_DEFAULT_NAMES = {"json": "mcpthreat-report.json", "sarif": "mcpthreat-report.sarif"}


class ExportScreen(ModalScreen):
    """Choose a format, confirm the file name, press Enter."""

    AUTO_FOCUS = "#export-path"

    BINDINGS = [Binding("escape", "close", "Cancel")]

    def __init__(self, report: dict, *, sarif: bool = True) -> None:
        super().__init__()
        self._report = report
        self._formats = ["json", "sarif"] if sarif else ["json"]

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Static(Text("Export report", style="bold"), classes="dialog-title")
            yield OptionList(
                *(Option(name.upper(), id=name) for name in self._formats), id="export-format"
            )
            yield Input(value=_DEFAULT_NAMES["json"], id="export-path")
            yield Static(
                Text("Enter = save in the current folder · ↑↓ on the list = format · Esc = cancel"),
                id="export-status",
                classes="dialog-hint",
            )

    def on_mount(self) -> None:
        self.query_one("#export-format", OptionList).highlighted = 0

    def _format(self) -> str:
        highlighted = self.query_one("#export-format", OptionList).highlighted
        return self._formats[highlighted if highlighted is not None else 0]

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        # Follow the format with the default file name, but never overwrite a name the user typed.
        field = self.query_one("#export-path", Input)
        if field.value in _DEFAULT_NAMES.values():
            field.value = _DEFAULT_NAMES[str(event.option_id)]

    def _error(self, message: str) -> None:
        self.query_one("#export-status", Static).update(Text(message, style=SEVERITY_COLORS["ERROR"]))

    def on_input_submitted(self, event: Input.Submitted) -> None:
        value = event.value.strip()
        if not value:
            self._error("Enter a file name.")
            return
        path = Path(value).expanduser()
        if path.is_dir():
            self._error("That is a folder; enter a file name.")
            return
        text = render_sarif(self._report) if self._format() == "sarif" else render_json(self._report)
        if path.exists():
            self.app.push_screen(
                ConfirmScreen(f"Overwrite {path}?", "The existing file will be replaced.", confirm_label="Overwrite"),
                lambda confirmed: self._write(path, text) if confirmed else None,
            )
        else:
            self._write(path, text)

    def _write(self, path: Path, text: str) -> None:
        try:
            path.write_text(text, encoding="utf-8")
        except OSError as exc:
            self._error(f"Could not save: {exc}")
            return
        self.app.notify(f"Report saved: {path}")
        self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)
