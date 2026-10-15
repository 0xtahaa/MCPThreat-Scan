"""Color system of the TUI (Autorea brand): one place for every color. The registered Textual
theme and the severity coloring in tui/screens/results.py both read from here. Deliberately
defined only in tui/, not in core/. Without truecolor support Textual/Rich downgrades the hex
values to the nearest 256/16-color match on its own."""

from __future__ import annotations

from textual.theme import Theme

# Autorea brand palette
BACKGROUND = "#101613"
SURFACE = "#18241D"
SELECTED = "#2F4A3A"
BRAND_GREEN = "#2F4A3A"
ACCENT = "#CFE9C8"
TEXT = "#E8F2EB"
TEXT_SECONDARY = "#AFC7B7"
TEXT_MUTED = "#799989"
BORDER = "#365344"

# Warning/error colors stay outside the brand greens so severity never reads as "brand".
SEVERITY_COLORS = {
    "ERROR": "#F0716B",
    "WARNING": "#E3B341",
    "INFO": "#7FB5D6",
}

MCP_SCANNER_THEME = Theme(
    name="mcp-scanner",
    primary=BRAND_GREEN,
    secondary=TEXT_SECONDARY,
    warning=SEVERITY_COLORS["WARNING"],
    error=SEVERITY_COLORS["ERROR"],
    success=ACCENT,
    accent=ACCENT,
    foreground=TEXT,
    background=BACKGROUND,
    surface=SURFACE,
    panel=SURFACE,
    dark=True,
    variables={
        "border": BORDER,
        "text-muted": TEXT_MUTED,
        "block-cursor-background": SELECTED,
        "block-cursor-foreground": TEXT,
        "footer-key-foreground": ACCENT,
    },
)
