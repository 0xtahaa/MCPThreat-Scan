"""Trusted servers and exclusions in one place, with their separate stores and rules.

Two different things live here and the screen keeps saying so:
- Trusted servers: a record that a file was reviewed at one exact fingerprint. No scan reads
  it; it neither makes a server secure nor hides a finding.
- Exclusions: (file, category) rules in .mcpscannerignore that hide findings in future scans.
"""

from __future__ import annotations

from pathlib import Path

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Select, Static

import mcpthreat_scan.policy.reputation as reputation_store
from mcpthreat_scan.core.models import VULNERABILITY_CATEGORIES
from mcpthreat_scan.policy.ignore import add_ignore_rule, load_ignore_rules, remove_ignore_rule
from mcpthreat_scan.policy.reputation import list_reviewed, revoke_review
from mcpthreat_scan.tui.screens.confirm import ConfirmScreen
from mcpthreat_scan.tui.theme import ACCENT, SEVERITY_COLORS, TEXT_MUTED

_IGNORE_FILE = ".mcpscannerignore"
_RULE_CATEGORIES = [*VULNERABILITY_CATEGORIES, "Scan Coverage"]


def _source_line(path: Path) -> Text:
    note = "" if path.exists() else "  (not created yet)"
    return Text(f"Source: {path}{note}", style=TEXT_MUTED)


class IgnoreRuleScreen(ModalScreen):
    """Add or edit one exclusion; dismisses with (file, category) or None."""

    AUTO_FOCUS = "#rule-file"

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, file: str = "", category: str = "") -> None:
        super().__init__()
        self._file = file
        self._category = category if category in _RULE_CATEGORIES else _RULE_CATEGORIES[0]
        self._editing = bool(file)

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Static(
                Text("Edit exclusion" if self._editing else "Add exclusion", style="bold"),
                classes="dialog-title",
            )
            yield Static(
                Text("File path exactly as the findings list shows it. Findings of the chosen "
                     "category in this file are hidden in future scans."),
                classes="dialog-detail",
            )
            yield Input(value=self._file, placeholder="path/to/file.py", id="rule-file")
            yield Select([(c, c) for c in _RULE_CATEGORIES], value=self._category, allow_blank=False, id="rule-category")
            yield Static("", id="rule-status", classes="dialog-hint")
            with Horizontal(classes="dialog-buttons"):
                yield Button("Save", id="save", variant="primary")
                yield Button("Cancel", id="cancel")

    def _save(self) -> None:
        file = self.query_one("#rule-file", Input).value.strip()
        if not file:
            self.query_one("#rule-status", Static).update(Text("Enter a file path.", style=SEVERITY_COLORS["ERROR"]))
            return
        self.dismiss((file, str(self.query_one("#rule-category", Select).value)))

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._save()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save":
            self._save()
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class TrustScreen(Screen):
    """Trusted servers and exclusions, each with scope and configuration source."""

    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("a", "add_exclusion", "Add exclusion"),
        Binding("e", "edit_exclusion", "Edit exclusion"),
        Binding("d", "remove_selected", "Remove selected"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._exclusions: dict[str, tuple[str, str]] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Trusted Servers & Exclusions", classes="step-title")
        yield Static(
            Text(
                "Trust and analysis are separate. A trusted entry only records that you reviewed a file; "
                "it does not make a server secure, does not hide findings, and no scan reads it. "
                "Exclusions are different: they hide findings in future scans."
            ),
            id="trust-note",
        )
        with VerticalScroll(id="trust-body"):
            yield Static(id="trusted-title", classes="section-title")
            yield Static(id="trusted-source", classes="section-source")
            yield DataTable(id="trusted-table")
            yield Static(id="exclusions-title", classes="section-title")
            yield Static(id="exclusions-source", classes="section-source")
            yield DataTable(id="exclusions-table")
        yield Footer()

    def on_mount(self) -> None:
        for table_id in ("#trusted-table", "#exclusions-table"):
            table = self.query_one(table_id, DataTable)
            table.cursor_type = "row"
        self._reload()
        self.query_one("#trusted-table", DataTable).focus()

    def _reload(self) -> None:
        reviewed = list_reviewed()
        trusted = self.query_one("#trusted-table", DataTable)
        trusted.clear(columns=True)
        trusted.add_columns("Server", "Last reviewed", "Fingerprint (SHA-256)")
        for name, entry in sorted(reviewed.items()):
            reviewed_at = " ".join(str(entry.get("reviewed_at", "-"))[:16].split("T"))
            trusted.add_row(name, reviewed_at, str(entry.get("version_hash", "-"))[:12], key=name)
        self.query_one("#trusted-title", Static).update(Text(f"TRUSTED SERVERS  {len(reviewed)}", style=f"bold {ACCENT}"))
        self.query_one("#trusted-source", Static).update(
            Text("Scope: one file, matched by the exact contents; any change invalidates the entry.\n"
                 "Keys: d = revoke trust\n", style=TEXT_MUTED).append_text(_source_line(reputation_store.DEFAULT_STORE_PATH))
        )

        rules = sorted(load_ignore_rules(_IGNORE_FILE))
        self._exclusions = {f"{index}": rule for index, rule in enumerate(rules)}
        exclusions = self.query_one("#exclusions-table", DataTable)
        exclusions.clear(columns=True)
        exclusions.add_columns("File", "Category")
        for key, (file, category) in self._exclusions.items():
            exclusions.add_row(file, category, key=key)
        self.query_one("#exclusions-title", Static).update(Text(f"EXCLUSIONS  {len(rules)}", style=f"bold {ACCENT}"))
        self.query_one("#exclusions-source", Static).update(
            Text("Scope: findings of the category in that file (path as reported), in every scan started "
                 "from this folder.\nKeys: a = add · e = edit · d = remove\n", style=TEXT_MUTED)
            .append_text(_source_line(Path(_IGNORE_FILE).resolve()))
        )

    def action_back(self) -> None:
        self.app.pop_screen()

    def _selected(self, table_id: str) -> str | None:
        table = self.query_one(table_id, DataTable)
        if table.row_count == 0 or table.cursor_row is None:
            return None
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        return row_key.value

    def action_remove_selected(self) -> None:
        if self.focused is self.query_one("#exclusions-table", DataTable):
            key = self._selected("#exclusions-table")
            if key is None:
                return
            file, category = self._exclusions[key]
            self.app.push_screen(
                ConfirmScreen(
                    "Remove this exclusion?",
                    f"“{category}” findings in {file} will appear in scans again.",
                    confirm_label="Remove",
                ),
                lambda confirmed: self._remove_exclusion(file, category) if confirmed else None,
            )
        else:
            name = self._selected("#trusted-table")
            if name is None:
                return
            self.app.push_screen(
                ConfirmScreen(
                    f"Revoke trust for “{name}”?",
                    "The stored review fingerprint is deleted. Scans and findings are not affected.",
                    confirm_label="Revoke",
                ),
                lambda confirmed: self._revoke(name) if confirmed else None,
            )

    def _remove_exclusion(self, file: str, category: str) -> None:
        remove_ignore_rule(file, category)
        self.notify(f"Exclusion removed: {category} in {Path(file).name}")
        self._reload()

    def _revoke(self, name: str) -> None:
        revoke_review(name)
        self.notify(f"Trust revoked: {name}")
        self._reload()

    def action_add_exclusion(self) -> None:
        self.app.push_screen(IgnoreRuleScreen(), self._apply_new_rule)

    def action_edit_exclusion(self) -> None:
        key = self._selected("#exclusions-table")
        if key is None:
            return
        file, category = self._exclusions[key]

        def apply(result: tuple[str, str] | None) -> None:
            if result is None or result == (file, category):
                return
            remove_ignore_rule(file, category)
            self._apply_new_rule(result)

        self.app.push_screen(IgnoreRuleScreen(file, category), apply)

    def _apply_new_rule(self, result: tuple[str, str] | None) -> None:
        if result is None:
            return
        file, category = result
        if add_ignore_rule(file, category):
            self.notify(f"Exclusion saved: {category} in {Path(file).name}")
        else:
            self.notify("That exclusion already exists.", severity="warning")
        self._reload()
