"""Pure display helpers shared by the TUI screens (no widgets, no scanner logic).

Everything that comes from a scan (messages, paths, evidence) is treated as plain data: it is
only ever appended to rich Text objects, never parsed as markup."""

from __future__ import annotations

from pathlib import Path

from rich.text import Text

from mcpthreat_scan.tui.theme import SEVERITY_COLORS, TEXT_MUTED

# Report levels (ERROR/WARNING/INFO, same as CLI and SARIF) as shown to people.
SEVERITY_LABELS = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "INFO"}


def severity_label(severity: str) -> str:
    return SEVERITY_LABELS.get(severity, severity)


def severity_text(severity: str) -> Text:
    """The severity label in its fixed color (the only warning colors in the interface)."""
    color = SEVERITY_COLORS.get(severity)
    return Text(severity_label(severity), style=f"bold {color}" if color else "bold")


def shorten_left(value: str, width: int) -> str:
    """Keep the end of a long path (the project folder is the informative part)."""
    if width < 8 or len(value) <= width:
        return value
    return "…" + value[-(width - 1):]


def display_path(file: str, target: str | None) -> str:
    """The file path relative to the scanned folder when it lies below it, else as reported."""
    if target:
        try:
            return Path(file).resolve().relative_to(Path(target).resolve()).as_posix()
        except (ValueError, OSError):
            pass
    return file


def location(finding: dict, target: str | None) -> str:
    """"tools/mail_server.py:47" (or just the path when the finding has no line)."""
    text = display_path(finding["file"], target)
    if finding["line"] is not None:
        text += f":{finding['line']}"
    return text


def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes, rest = divmod(int(seconds), 60)
    return f"{minutes} min {rest:02d} s"


def labeled(label: str, value: str | Text, width: int = 16) -> Text:
    """One "Label   value" row with a muted label column."""
    row = Text()
    row.append(f"{label:<{width}}", style=TEXT_MUTED)
    row.append(value) if isinstance(value, str) else row.append_text(value)
    return row
