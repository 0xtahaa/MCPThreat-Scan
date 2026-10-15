"""Scan summary screen (step 3): what was scanned, how it ended and what was found.

Security findings and scanner notes (a file or check was skipped) are counted separately, so a
skipped check never looks like a vulnerability. A scan that fails never reaches this screen -
the error is shown as a notification and recorded on the main menu instead."""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, OptionList, Static
from textual.widgets.option_list import Option

from mcpthreat_scan.core.models import is_scanner_note
from mcpthreat_scan.tui.display import format_duration, labeled, severity_text, shorten_left
from mcpthreat_scan.tui.screens.export import ExportScreen
from mcpthreat_scan.tui.screens.results import ResultsScreen
from mcpthreat_scan.tui.theme import ACCENT, TEXT_MUTED

_SEVERITY_ROWS = ("ERROR", "WARNING", "INFO")


def summary_text(
    report: dict, *, duration_s: float, ai_review: bool, files_in_scope: int | None, width: int = 80
) -> Text:
    """The summary block, built only from the report and the measured run."""
    findings = [f for f in report["findings"] if not is_scanner_note(f)]
    notes = [f for f in report["findings"] if is_scanner_note(f)]
    suppressed = report["summary"].get("suppressed_count", 0)

    text = Text()
    text.append_text(labeled("Target", shorten_left(report["target"], max(width - 16, 20))))
    text.append("\n")
    text.append_text(labeled("Status", Text("Completed", style=f"bold {ACCENT}")))
    text.append("\n")
    text.append_text(
        labeled("Files in scope", f"{files_in_scope} source file(s)" if files_in_scope is not None else "-")
    )
    text.append("\n")
    text.append_text(labeled("Duration", format_duration(duration_s)))
    text.append("\n")
    text.append_text(labeled("AI review", "on" if ai_review else "off"))
    text.append("\n\n")
    text.append_text(labeled("Total findings", Text(str(len(findings)), style="bold")))
    for severity in _SEVERITY_ROWS:
        count = sum(1 for f in findings if f["severity"] == severity)
        label = severity_text(severity)
        text.append("\n  ")
        text.append_text(label)
        text.append(" " * (12 - len(label)) + str(count))
    if notes:
        text.append("\n\n")
        text.append_text(labeled("Scanner notes", f"{len(notes)} (checks or files skipped; not security findings)"))
    if suppressed:
        text.append("\n")
        text.append_text(labeled("Hidden", f"{suppressed} finding(s) hidden by ignore rules"))
    if not findings:
        text.append("\n\n")
        text.append(
            "No findings. This does not prove the server is safe: only the checks listed in Help ran.",
            style=TEXT_MUTED,
        )
    return text


class ScanSummaryScreen(Screen):
    """Result of a finished scan with the next actions."""

    AUTO_FOCUS = "#summary-actions"

    BINDINGS = [
        Binding("escape", "back", "Main menu"),
        Binding("f", "findings", "Findings"),
        Binding("e", "export", "Export"),
    ]

    def __init__(
        self, report: dict, *, duration_s: float, ai_review: bool = False, files_in_scope: int | None = None
    ) -> None:
        super().__init__()
        self._report = report
        self._duration_s = duration_s
        self._ai_review = ai_review
        self._files_in_scope = files_in_scope

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Step 3 of 3 · Scan summary", classes="step-title")
        with VerticalScroll(id="summary-body"):
            yield Static(id="summary-card")
            yield OptionList(
                Option("View findings", id="findings", disabled=not self._report["findings"]),
                Option("Export report (JSON / SARIF)", id="export"),
                Option("Back to main menu", id="menu"),
                id="summary-actions",
            )
        yield Footer()

    def on_mount(self) -> None:
        self._render_card()

    def on_resize(self) -> None:
        self._render_card()

    def _render_card(self) -> None:
        card = self.query_one("#summary-card", Static)
        card.update(
            summary_text(
                self._report,
                duration_s=self._duration_s,
                ai_review=self._ai_review,
                files_in_scope=self._files_in_scope,
                width=self.size.width,
            )
        )

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_id == "findings":
            self.action_findings()
        elif event.option_id == "export":
            self.action_export()
        else:
            self.action_back()

    def action_findings(self) -> None:
        if self._report["findings"]:
            self.app.push_screen(ResultsScreen(self._report))

    def action_export(self) -> None:
        self.app.push_screen(ExportScreen(self._report))

    def action_back(self) -> None:
        # The path and confirm screens of the wizard (marked WIZARD_STEP) are still below this one.
        self.app.pop_screen()
        while getattr(self.app.screen, "WIZARD_STEP", False):
            self.app.pop_screen()
