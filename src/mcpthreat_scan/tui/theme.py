"""Color system of the TUI: one accent color for branding, severity colors as the single
source of truth - both for the registered Textual theme and for the table coloring in
tui/screens/results.py. Deliberately defined only here in tui/, not in core/ (no change
to existing core logic needed).
"""

from __future__ import annotations

from textual.theme import Theme

ACCENT = "#5DCAA5"

SEVERITY_COLORS = {
    "ERROR": "#E24B4A",
    "WARNING": "#EF9F27",
    "INFO": "#378ADD",
}

MCP_SCANNER_THEME = Theme(
    name="mcp-scanner",
    primary=ACCENT,
    secondary=SEVERITY_COLORS["INFO"],
    warning=SEVERITY_COLORS["WARNING"],
    error=SEVERITY_COLORS["ERROR"],
    success=ACCENT,
    accent=ACCENT,
    dark=True,
)
