"""Header texts of the TUI: the wordmark (ASCII lettering plus info line) and a compact fallback.

Both show brand, product, tagline, version and status; the wordmark is used whenever the terminal
is wide enough, the compact text otherwise."""

from __future__ import annotations

from functools import lru_cache
from importlib.metadata import PackageNotFoundError, version

import pyfiglet
from rich.text import Text

from mcpthreat_scan.tui.theme import ACCENT, TEXT_MUTED, TEXT_SECONDARY

DISPLAY_NAME = "MCPThreat-Scan"
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


@lru_cache(maxsize=None)
def _lettering() -> tuple[str, ...]:
    """The product name as figlet lines (font "small" fits into 80 columns), trailing blank lines dropped."""
    lines = [line.rstrip() for line in pyfiglet.figlet_format(DISPLAY_NAME, font="small").splitlines()]
    while lines and not lines[-1]:
        lines.pop()
    return tuple(lines)


def _info_line(status: str) -> Text:
    info = Text()
    info.append(BRAND, style=f"bold {ACCENT}")
    info.append(" · ", style=TEXT_MUTED)
    info.append(TAGLINE, style=TEXT_SECONDARY)
    info.append(" · ", style=TEXT_MUTED)
    info.append(get_version(), style=TEXT_MUTED)
    info.append(" · Status: ", style=TEXT_MUTED)
    info.append(status, style=f"bold {ACCENT}")
    return info


def render_wordmark(status: str = "READY") -> Text:
    """The ASCII lettering of the product name with the info line (brand, tagline, version, status) below."""
    text = Text(no_wrap=True)
    for line in _lettering():
        text.append(f"{line}\n", style=f"bold {ACCENT}")
    text.append_text(_info_line(status))
    return text


def wordmark_width() -> int:
    """Columns the wordmark needs (the widest of lettering and info line)."""
    return max(max((len(line) for line in _lettering()), default=0), len(_info_line("READY")))
