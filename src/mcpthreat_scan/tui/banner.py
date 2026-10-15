"""Compact header text of the TUI: brand, product, tagline, version and status."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from rich.text import Text

from mcpthreat_scan.tui.theme import ACCENT, TEXT_MUTED, TEXT_SECONDARY

BRAND = "AUTOREA"
PRODUCT = "MCP THREAT SCAN"
TAGLINE = "Zero-Execution Static Analysis"
REPO_URL = "https://github.com/0xtahaa/MCP-scanner-"


def get_version() -> str:
    """Installed package version (single source: pyproject.toml); "unknown" if not installed."""
    try:
        return f"v{version('mcpthreat-scan')}"
    except PackageNotFoundError:
        return "unknown"


def render_header(status: str = "READY") -> Text:
    """Three lines: brand / product, tagline, version and status."""
    text = Text()
    text.append(BRAND, style=f"bold {ACCENT}")
    text.append(" / ", style=TEXT_MUTED)
    text.append(PRODUCT, style="bold")
    text.append(f"\n{TAGLINE}", style=TEXT_SECONDARY)
    text.append(f"\nVersion: {get_version()}  ·  Status: ", style=TEXT_MUTED)
    text.append(status, style=f"bold {ACCENT}")
    return text
