"""Version comparison result: what changed between a baseline and the current version, and why
that may matter for a server that was reviewed before.

All content comes from run_version_comparison(); the "why" lines are counts and the scanner's own
messages, not interpretation added here."""

from __future__ import annotations

import re
from pathlib import Path

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from mcpthreat_scan.tui.display import display_path, format_duration, labeled, severity_text
from mcpthreat_scan.tui.screens.export import ExportScreen
from mcpthreat_scan.tui.screens.results import ResultsScreen, row_text
from mcpthreat_scan.tui.theme import ACCENT, SEVERITY_COLORS, TEXT_MUTED

_LIST_LIMIT = 12
_HIDDEN_BEHAVIOR_RULE = "rugpull-behavior-changed-hidden"


def _heading(text: Text, title: str, count: int | None = None) -> None:
    text.append("\n\n" if len(text) else "")
    text.append(title.upper(), style=f"bold {ACCENT}")
    if count is not None:
        text.append(f"  {count}", style=TEXT_MUTED)
    text.append("\n")


def _file_list(text: Text, label: str, names: list[str]) -> None:
    if not names:
        return
    text.append_text(labeled(label, f"{len(names)}", width=10))
    text.append("\n")
    for name in names[:_LIST_LIMIT]:
        text.append(f"   {name}\n", style=TEXT_MUTED)
    if len(names) > _LIST_LIMIT:
        text.append(f"   … and {len(names) - _LIST_LIMIT} more\n", style=TEXT_MUTED)


def review_lines(result: dict) -> list[Text]:
    """Facts that explain why a reviewed server may have become unsafe; empty if nothing changed."""
    lines = []
    hidden = [c for c in result["tool_changes"] if c["rule_id"] == _HIDDEN_BEHAVIOR_RULE]
    for change in hidden:
        match = re.search(r"Tool '([^']+)'", change["message"])
        tool = f"Tool '{match.group(1)}'" if match else "A tool"
        lines.append(
            Text(f"{tool} changed its code while its parameters and description stayed identical.",
                 style=SEVERITY_COLORS["ERROR"])
        )
    visible = len(result["tool_changes"]) - len(hidden)
    if visible:
        lines.append(Text(f"{visible} other change(s) to tool definitions (tools added, removed, parameters or description changed)."))
    new = result["new_findings"]
    if new:
        high = sum(1 for f in new if f["severity"] == "ERROR")
        suffix = f", {high} of them HIGH" if high else ""
        lines.append(Text(f"{len(new)} new finding(s) in the current version{suffix}."))
    if result["resolved_findings"]:
        lines.append(Text(f"{len(result['resolved_findings'])} finding(s) from the baseline no longer appear."))
    return lines


def comparison_text(result: dict, *, duration_s: float) -> Text:
    """The whole comparison as one scrollable text."""
    files = result["files"]
    text = Text()
    text.append_text(labeled("Baseline", result["before"], width=10))
    text.append("\n")
    text.append_text(labeled("Current", result["after"], width=10))
    text.append("\n")
    mode = "two folders" if result["mode"] == "folders" else "two files"
    text.append_text(labeled("Compared", f"{mode} · {format_duration(duration_s)}", width=10))

    _heading(text, "Review summary")
    review = review_lines(result)
    if review:
        for line in review:
            text.append("• ")
            text.append_text(line)
            text.append("\n")
    else:
        text.append("No changes to tool definitions or findings between these versions.\n")
        if files["modified"] or files["added"] or files["removed"]:
            text.append("Files did change, but none of the enabled checks reacted to it.\n", style=TEXT_MUTED)
    text.append("A clean result is not proof of safety: only the checks listed in Help ran.", style=TEXT_MUTED)

    changed = len(files["added"]) + len(files["removed"]) + len(files["modified"])
    _heading(text, "Files", changed)
    if changed:
        _file_list(text, "Added", files["added"])
        _file_list(text, "Removed", files["removed"])
        _file_list(text, "Modified", files["modified"])
    else:
        text.append("No file changed.\n", style=TEXT_MUTED)

    _heading(text, "Tool definition changes", len(result["tool_changes"]))
    if not result["tool_changes"]:
        text.append("None.\n", style=TEXT_MUTED)
    for change in result["tool_changes"]:
        text.append_text(severity_text(change["severity"]))
        shown = display_path(change["file"], result["after"]) if result["mode"] == "folders" else Path(change["file"]).name
        text.append(f"  {shown}\n", style=TEXT_MUTED)
        text.append(f"      {change['message']}\n")

    _heading(text, "New findings", len(result["new_findings"]))
    if not result["new_findings"]:
        text.append("None.\n", style=TEXT_MUTED)
    for finding in result["new_findings"]:
        text.append_text(row_text(finding, result["after"] if result["mode"] == "folders" else None))
        text.append("\n")

    _heading(text, "Resolved findings", len(result["resolved_findings"]))
    if not result["resolved_findings"]:
        text.append("None.\n", style=TEXT_MUTED)
    for finding in result["resolved_findings"]:
        text.append_text(row_text(finding, result["before"] if result["mode"] == "folders" else None))
        text.append("\n")

    text.append(f"\n{result['unchanged_count']} finding(s) are present in both versions.", style=TEXT_MUTED)
    return text


class ComparisonScreen(Screen):
    """Scrollable comparison report with export and a shortcut to the new findings."""

    BINDINGS = [
        Binding("escape", "back", "Main menu"),
        Binding("n", "new_findings", "New findings"),
        Binding("e", "export", "Export JSON"),
    ]

    def __init__(self, result: dict, *, duration_s: float) -> None:
        super().__init__()
        self._result = result
        self._duration_s = duration_s

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Step 4 of 4 · Version comparison", classes="step-title")
        with VerticalScroll(id="comparison-body"):
            yield Static(comparison_text(self._result, duration_s=self._duration_s), id="comparison")
        yield Footer()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_new_findings(self) -> None:
        if self._result["new_findings"]:
            self.app.push_screen(
                ResultsScreen(
                    {"target": self._result["after"], "findings": self._result["new_findings"], "summary": {}}
                )
            )

    def action_export(self) -> None:
        self.app.push_screen(ExportScreen(self._result, sarif=False))
