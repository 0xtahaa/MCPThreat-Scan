"""Workspace state of the running TUI: what the main menu shows about the last run.

Plain attributes on the app object (declared in MCPScannerApp.__init__), written only from real
scan/comparison outcomes. Works with any Textual App object, so screens can be hosted standalone."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from textual.app import App


def set_target(app: App, target: Path) -> None:
    """Remember the target the user picked for the next scan."""
    app.current_target = target


def record_run(
    app: App,
    kind: str,
    target: str,
    status: str,
    *,
    duration_s: float,
    ai_review: bool = False,
    error: str | None = None,
    report: dict | None = None,
) -> None:
    """Store the outcome of a scan ("scan") or version comparison ("compare").

    status is "completed" or "failed". Only a completed scan replaces the findings that the main
    menu's "View Findings" opens."""
    app.last_run = {
        "kind": kind,
        "target": target,
        "status": status,
        "finished_at": datetime.now(),
        "duration_s": duration_s,
        "ai_review": ai_review,
        "error": error,
    }
    if status == "completed" and kind == "scan":
        app.last_report = report
