"""ASCII art banner for the TUI main menu - display name, not the project/folder name.

Uses pyfiglet instead of hand-drawn block letters (terminals have no font size -
"large" here means: letters composed of several characters).
"""

from __future__ import annotations

import pyfiglet

DISPLAY_NAME = "MCPThreat-Scan"
COMPANY = "Autorea"
VERSION = "v0.1.0"
TAGLINE = "Zero-Execution Static Analysis for MCP Server Source Code"
REPO_URL = "https://github.com/0xtahaa/MCP-scanner-"


def render_ascii_logo() -> str:
    """Build the ASCII lettering of the display name (font "small" - fits into 80 columns)."""
    return pyfiglet.figlet_format(DISPLAY_NAME, font="small")


def render_info_line() -> str:
    """Build the line with company/version/tagline plus the link below it.

    Separator is deliberately ASCII ("|") instead of a Unicode middle dot - on some
    Windows console code pages a Unicode special character was rendered incorrectly here
    (same class of problem as the documented umlaut bug from P8-4).
    """
    return f"{COMPANY} | {VERSION} | {TAGLINE}\n{REPO_URL}"
