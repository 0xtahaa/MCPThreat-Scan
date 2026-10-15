"""Findings screen: a keyboard-navigable list of findings with a detail panel below it.

Everything shown comes from the report (category, severity, file, line, message, rule id,
evidence) or from the static remediation text of the category. Scanner notes (a file or check
was skipped) are kept apart from security findings and reachable through their own filter."""

from __future__ import annotations

from pathlib import Path

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, ListItem, ListView, Static

from mcpthreat_scan.core.models import SEVERITY_ORDER, is_scanner_note, recommendation_for
from mcpthreat_scan.policy.ignore import add_ignore_rule
from mcpthreat_scan.tui.display import labeled, location, severity_text
from mcpthreat_scan.tui.screens.confirm import ConfirmScreen
from mcpthreat_scan.tui.screens.export import ExportScreen
from mcpthreat_scan.tui.theme import ACCENT, TEXT_MUTED

# View filters in the order the "f" key cycles through them.
_FILTERS = ("all", "ERROR", "WARNING", "INFO", "notes")
_FILTER_NAMES = {"all": "All", "ERROR": "High", "WARNING": "Medium", "INFO": "Info", "notes": "Notes"}
_NO_FINDINGS = "No findings. This does not prove the server is safe: only the checks listed in Help ran."


def _sort_key(finding: dict) -> tuple:
    return (-SEVERITY_ORDER[finding["severity"]], finding["file"], finding["line"] or 0)


def row_text(finding: dict, target: str | None) -> Text:
    """One list row: severity, category, location."""
    row = Text()
    if is_scanner_note(finding):
        row.append("NOTE   ", style=TEXT_MUTED)
    else:
        label = severity_text(finding["severity"])
        row.append_text(label)
        row.append(" " * (7 - len(label)))
    row.append(finding["category"])
    row.append(f"  ·  {location(finding, target)}", style=TEXT_MUTED)
    return row


def detail_text(finding: dict, target: str | None) -> Text:
    """The full picture of one finding for the detail panel."""
    note = is_scanner_note(finding)
    detail = Text()
    if note:
        detail.append("NOTE", style=f"bold {TEXT_MUTED}")
    else:
        detail.append_text(severity_text(finding["severity"]))
    detail.append(f" — {finding['category']}\n\n", style="bold")
    detail.append_text(labeled("File", location(finding, target), width=16))
    detail.append("\n")
    if finding.get("rule_id"):
        detail.append_text(labeled("Rule", finding["rule_id"], width=16))
        detail.append("\n")
    detail.append_text(labeled("Report level", finding["severity"], width=16))
    detail.append("\n\nDescription\n", style=f"bold {ACCENT}")
    detail.append(finding["message"])
    if finding.get("evidence"):
        detail.append("\n\nEvidence\n", style=f"bold {ACCENT}")
        detail.append(finding["evidence"], style="italic")
    detail.append("\n\nRecommendation\n", style=f"bold {ACCENT}")
    detail.append(recommendation_for(finding))
    return detail


class FindingItem(ListItem):
    """One list row for exactly one finding (full text lives in the detail panel)."""

    def __init__(self, finding: dict, target: str | None) -> None:
        super().__init__(classes="finding-row")
        self.finding = finding
        self._target = target

    def compose(self) -> ComposeResult:
        yield Static(row_text(self.finding, self._target))


class ResultsScreen(Screen):
    """Show the findings of a scan report: list on top, details of the highlighted one below."""

    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("f", "cycle_filter", "Filter severity"),
        Binding("i", "ignore_selected", "Ignore"),
        Binding("e", "export", "Export"),
    ]

    def __init__(self, report: dict) -> None:
        super().__init__()
        self._report = report
        self._target = report.get("target")
        self._rows = sorted(report["findings"], key=_sort_key)
        self._filter = "all"

    def _visible(self) -> list[dict]:
        if self._filter == "notes":
            return [f for f in self._rows if is_scanner_note(f)]
        findings = [f for f in self._rows if not is_scanner_note(f)]
        if self._filter == "all":
            return findings
        return [f for f in findings if f["severity"] == self._filter]

    def _filter_bar(self) -> Text:
        findings = [f for f in self._rows if not is_scanner_note(f)]
        counts = {
            "all": len(findings),
            "notes": len(self._rows) - len(findings),
            **{s: sum(1 for f in findings if f["severity"] == s) for s in ("ERROR", "WARNING", "INFO")},
        }
        bar = Text()
        for index, name in enumerate(_FILTERS):
            if index:
                bar.append("   ", style=TEXT_MUTED)
            active = name == self._filter
            bar.append(f"{_FILTER_NAMES[name]} {counts[name]}", style=f"bold {ACCENT} underline" if active else TEXT_MUTED)
        return bar

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(id="filter-bar")
        yield ListView(id="findings-list")
        with VerticalScroll(id="finding-detail"):
            yield Static(id="detail")
        yield Footer()

    async def on_mount(self) -> None:
        await self._rebuild()

    async def _rebuild(self) -> None:
        """Refill the list for the current filter and show the first entry."""
        self.query_one("#filter-bar", Static).update(self._filter_bar())
        list_view = self.query_one(ListView)
        await list_view.clear()
        visible = self._visible()
        await list_view.extend(FindingItem(f, self._target) for f in visible)
        detail = self.query_one("#detail", Static)
        if visible:
            list_view.index = 0
            detail.update(detail_text(visible[0], self._target))
        elif self._filter == "all" and not self._rows:
            detail.update(Text(_NO_FINDINGS, style=TEXT_MUTED))
        else:
            detail.update(Text(f"No {_FILTER_NAMES[self._filter].lower()} entries in this view.", style=TEXT_MUTED))

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if isinstance(event.item, FindingItem):
            self.query_one("#detail", Static).update(detail_text(event.item.finding, self._target))
            self.query_one("#finding-detail").scroll_home(animate=False)

    async def action_cycle_filter(self) -> None:
        self._filter = _FILTERS[(_FILTERS.index(self._filter) + 1) % len(_FILTERS)]
        await self._rebuild()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_export(self) -> None:
        self.app.push_screen(ExportScreen(self._report))

    def action_ignore_selected(self) -> None:
        item = self.query_one(ListView).highlighted_child
        if not isinstance(item, FindingItem):
            return
        finding = item.finding
        name = Path(finding["file"]).name
        self.app.push_screen(
            ConfirmScreen(
                f"Hide “{finding['category']}” findings in {name}?",
                "All findings of this category in this file are hidden in future scans "
                "(stored in .mcpscannerignore). This does not fix anything. "
                "You can remove the rule again under Trusted Servers & Exclusions.",
                confirm_label="Hide",
            ),
            lambda confirmed: self._ignore(finding) if confirmed else None,
        )

    async def _ignore(self, finding: dict) -> None:
        add_ignore_rule(finding["file"], finding["category"])
        before = len(self._rows)
        self._rows = [
            f for f in self._rows
            if not (f["file"] == finding["file"] and f["category"] == finding["category"])
        ]
        self.notify(f"Hidden from future scans: {finding['category']} in {Path(finding['file']).name} "
                    f"({before - len(self._rows)} finding(s))")
        await self._rebuild()
