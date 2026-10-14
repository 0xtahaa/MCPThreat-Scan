"""Results screen: shows a report (from run_scan()/run_diff()) as a scrollable list of
cards - one card per finding, stacked vertically instead of side-by-side table columns
(so no horizontal scrolling is needed)."""

from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, ListItem, ListView, Static

from mcpthreat_scan.policy.ignore import add_ignore_rule
from mcpthreat_scan.tui.theme import SEVERITY_COLORS

_SEVERITY_LABELS = {
    "ERROR": "Critical",
    "WARNING": "Needs review",
    "INFO": "Note",
}


def _severity_markup(severity: str) -> str:
    """Color the severity label with the project-wide severity color (tui/theme.py)."""
    label = _SEVERITY_LABELS.get(severity, severity)
    color = SEVERITY_COLORS.get(severity)
    return f"[bold {color}]{label}[/]" if color else f"[bold]{label}[/]"


def _summary_text(report: dict) -> str:
    """Build a summary in plain words instead of raw category names."""
    findings = report["findings"]
    summary = report["summary"]
    if not findings:
        return "No problems found."

    critical_count = sum(1 for f in findings if f["severity"] == "ERROR")
    text = f"{len(findings)} problem(s) found"
    if critical_count:
        text += f", {critical_count} of them critical"
    text += (
        f". {summary['categories_without_finding']} of {summary['categories_checked']} "
        "checked categories without findings."
    )
    if summary.get("suppressed_count"):
        text += f" ({summary['suppressed_count']} more finding(s) hidden, see ignore list.)"
    return text


class FindingItem(ListItem):
    """One card for exactly one finding: severity/category, location and message stacked
    vertically instead of in table columns - always fully readable without horizontal
    scrolling, no matter how long the message is."""

    def __init__(self, finding_index: int, finding: dict) -> None:
        super().__init__(classes="finding-card")
        self.finding_index = finding_index
        self._finding = finding

    def compose(self) -> ComposeResult:
        finding = self._finding
        location = Path(finding["file"]).name
        if finding["line"] is not None:
            location += f":{finding['line']}"
        with Vertical():
            yield Static(
                f"{_severity_markup(finding['severity'])}  ·  {finding['category']}",
                classes="finding-head",
            )
            yield Static(location, classes="finding-location")
            yield Static(finding["message"], classes="finding-message")


class ResultsScreen(Screen):
    """Show the findings of a scan or diff report as a scrollable card list."""

    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("i", "ignore_selected", "Ignore"),
    ]

    def __init__(self, report: dict) -> None:
        super().__init__()
        self._report = report

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(_summary_text(self._report), id="summary")
        yield ListView(id="findings-list")
        yield Footer()

    def on_mount(self) -> None:
        list_view = self.query_one(ListView)
        for index, finding in enumerate(self._report["findings"]):
            list_view.append(FindingItem(index, finding))
        if self._report["findings"]:
            list_view.index = 0

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_ignore_selected(self) -> None:
        list_view = self.query_one(ListView)
        item = list_view.highlighted_child
        if item is None:
            return

        finding = self._report["findings"][item.finding_index]
        add_ignore_rule(finding["file"], finding["category"])

        self.notify(f"Ignored: {finding['category']} in {Path(finding['file']).name}")
        list_view.pop(list_view.index)
