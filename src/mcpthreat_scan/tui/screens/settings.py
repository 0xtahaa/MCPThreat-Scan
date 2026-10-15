"""Settings & help: where the configuration lives, the keyboard shortcuts and what is checked."""

from __future__ import annotations

import os
from pathlib import Path

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

import mcpthreat_scan.policy.reputation as reputation_store
from mcpthreat_scan.core.models import VULNERABILITY_CATEGORIES
from mcpthreat_scan.tui.banner import REPO_URL, get_version
from mcpthreat_scan.tui.display import labeled
from mcpthreat_scan.tui.screens.setup import SetupScreen
from mcpthreat_scan.tui.theme import ACCENT, TEXT_MUTED

_SHORTCUTS = [
    ("Everywhere", "↑↓ move · Enter select · Esc back"),
    ("Main menu", "S scan · D compare versions · ? this page · Q quit"),
    ("Path pickers", "type a path + Enter · s = select highlighted tree entry"),
    ("Findings", "F filter by severity · I hide a finding · E export · Esc back"),
    ("Scan summary", "F findings · E export · Esc main menu"),
    ("Comparison", "N new findings · E export JSON · Esc main menu"),
    ("Trusted & Exclusions", "Tab switch list · A add · E edit · D remove / revoke"),
]

# What each category stands for, taken from what the rules and stages really look for.
_CHECKS = [
    ("Tool Poisoning", "instructions aimed at an AI agent in tool descriptions or tool output"),
    ("Command Injection", "tool parameters flowing unchecked into a shell, eval or exec"),
    ("Hardcoded Secret", "API keys, tokens and secrets written as string literals"),
    ("Supply Chain", "known-vulnerable dependencies (requirements.txt, pyproject.toml, poetry.lock; "
                     "package-lock.json needs osv-scanner)"),
    ("Typosquatting / Shadow-Server", "declared server name very close to a well-known MCP server"),
    ("Header Leak", "request headers (tokens, cookies) placed into error messages or logs"),
    ("Unscoped Environment Access", "environment variables read on every call inside a handler"),
    ("Missing Audit Logging", "handlers without any logging call (a recommendation, INFO)"),
    ("Capability Mismatch", "handler uses network or email without its name or description saying so"),
]


def _section(text: Text, title: str) -> None:
    text.append("\n\n" if len(text) else "")
    text.append(title.upper(), style=f"bold {ACCENT}")
    text.append("\n")


def settings_text() -> Text:
    """Current settings and the full help, built from real state (paths, key presence, categories)."""
    has_key = bool(os.environ.get("OPENAI_API_KEY"))
    text = Text()
    text.append(f"Autorea MCP Threat Scan {get_version()}  ·  {REPO_URL}\n", style=TEXT_MUTED)

    _section(text, "Settings")
    text.append_text(labeled("Analysis", "static, zero-execution: scanned code is only read, never run", width=16))
    text.append("\n")
    text.append_text(labeled("AI review", "API key configured (opt-in per scan)" if has_key else "no API key set", width=16))
    text.append("\n")
    text.append_text(labeled("Exclusions", str(Path(".mcpscannerignore").resolve()), width=16))
    text.append("\n")
    text.append_text(labeled("Trust store", str(reputation_store.DEFAULT_STORE_PATH), width=16))
    text.append("\n")
    text.append_text(labeled("API key file", str(Path(".env").resolve()), width=16))
    text.append("\nPress K to set or replace the OpenAI API key (it is stored locally and never shown).\n", style=TEXT_MUTED)

    _section(text, "Keyboard")
    for where, keys in _SHORTCUTS:
        text.append_text(labeled(where, keys, width=22))
        text.append("\n")

    _section(text, "What is checked")
    for category in VULNERABILITY_CATEGORIES:
        description = dict(_CHECKS).get(category, "")
        text.append_text(labeled(category, description, width=32))
        text.append("\n")
    text.append_text(labeled("Rug Pull / Version Diff", "Compare Versions: tool changes and new or resolved findings", width=32))

    _section(text, "Good to know")
    text.append("• No finding does not prove a server is safe; only the checks above run.\n")
    text.append("• Trusted servers are a review record. They do not make a server secure and no scan uses them.\n")
    text.append("• Exclusions hide findings in future scans; remove them under Trusted Servers & Exclusions.\n")
    text.append("• Scanner notes (skipped files or checks) are shown apart from security findings.\n")
    text.append("• A running scan cannot be cancelled: the Semgrep stage is one external process.")
    return text


class SettingsScreen(Screen):
    """Read-only overview plus the one setting the TUI can change (the API key)."""

    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("k", "set_key", "API key"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Settings & Help", classes="step-title")
        with VerticalScroll(id="settings-body"):
            yield Static(settings_text(), id="settings")
        yield Footer()

    def on_screen_resume(self) -> None:
        self.query_one("#settings", Static).update(settings_text())

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_set_key(self) -> None:
        self.app.push_screen(SetupScreen(self.app.pop_screen))
