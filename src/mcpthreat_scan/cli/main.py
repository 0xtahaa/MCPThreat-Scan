# CLI commands: scan and diff, with text/json output.
# Analysis lives in mcpthreat_scan.core.orchestrator; this module only wires arguments to it.

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from functools import partial
from pathlib import Path

from mcpthreat_scan.core.exceptions import ReportError
from mcpthreat_scan.core.models import exceeds_severity_threshold
from mcpthreat_scan.core.orchestrator import run_diff, run_scan
from mcpthreat_scan.reporting.json import render_json
from mcpthreat_scan.reporting.sarif import render_sarif
from mcpthreat_scan.reporting.text import render_text

# Starts the interactive UI; callers may inject one (tests), default is the TUI app.
TuiRunner = Callable[[], None]


def _print_report(report: dict, output_format: str) -> None:
    """Print the report in the requested format (text is the default)."""
    if output_format == "json":
        print(render_json(report))
    elif output_format == "sarif":
        print(render_sarif(report))
    else:
        print(render_text(report))


def scan_command(args: argparse.Namespace) -> int:
    """Implements `scan <path> [--format text|json] [--ai-review] [--fail-on ERROR|WARNING|INFO]`.
    Returns a process exit code."""
    target_path = Path(args.path)
    if not target_path.exists():
        print(f"Path not found: {target_path}", file=sys.stderr)
        return 1

    try:
        report = run_scan(target_path, ai_review=args.ai_review)
    except ReportError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    _print_report(report, args.format)

    if args.fail_on and exceeds_severity_threshold(report["findings"], args.fail_on):
        return 1

    return 0


def diff_command(args: argparse.Namespace) -> int:
    """Compare two file versions for rug-pull changes; output in same format as scan."""
    before_path = Path(args.before)
    after_path = Path(args.after)
    if not before_path.exists():
        print(f"Path not found: {before_path}", file=sys.stderr)
        return 1
    if not after_path.exists():
        print(f"Path not found: {after_path}", file=sys.stderr)
        return 1

    try:
        report = run_diff(before_path, after_path)
    except ReportError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    _print_report(report, args.format)

    return 0


def tui_command(args: argparse.Namespace, run_tui: TuiRunner | None = None) -> int:
    """Implements `tui` - starts the interactive Textual interface (starter can optionally be injected)."""
    if run_tui is None:
        # Imported lazily so plain scan/diff runs never load Textual.
        from mcpthreat_scan.tui.app import run as run_tui

    run_tui()
    return 0


def build_parser(run_tui: TuiRunner | None = None) -> argparse.ArgumentParser:
    """Build the CLI argument parser for 'scan' and 'diff' commands."""
    parser = argparse.ArgumentParser(
        prog="mcpthreat-scan",
        description="Static zero-execution security scanner for MCP server source code.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan", help="Scans a file or a folder containing MCP server source code."
    )
    scan_parser.add_argument(
        "path", help="Path to the file or folder to scan."
    )
    scan_parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format: human-readable text (default), JSON or SARIF (industry standard "
        "for GitHub Code Scanning/CI security tools).",
    )
    # Opt-in flag: Layer-2 AI review per Tool Poisoning candidate requires an API call.
    scan_parser.add_argument(
        "--ai-review",
        action="store_true",
        help="Automatically runs the hardened layer-2 AI review (P3-1) for every tool "
        "poisoning candidate instead of only flagging it as a candidate. "
        "Requires OPENAI_API_KEY; if the key is missing the scan does NOT abort - the "
        "candidate stays unconfirmed with a clear note.",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["ERROR", "WARNING", "INFO"],
        default=None,
        help="Returns exit code 1 as soon as a finding is at least as severe as this "
        "level (order: INFO < WARNING < ERROR). Without this flag the "
        "exit code is always 0, as before.",
    )
    scan_parser.set_defaults(func=scan_command)

    diff_parser = subparsers.add_parser(
        "diff",
        help="Compares two versions of the same file for rug-pull changes "
        "(tool name/parameters/docstring/hidden behavior).",
    )
    diff_parser.add_argument("before", help="Path to the OLDER version of the file.")
    diff_parser.add_argument("after", help="Path to the NEWER version of the same file.")
    diff_parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format: human-readable text (default), JSON or SARIF (industry standard "
        "for GitHub Code Scanning/CI security tools).",
    )
    diff_parser.set_defaults(func=diff_command)

    tui_parser = subparsers.add_parser(
        "tui", help="Starts the interactive terminal interface (Textual)."
    )
    tui_parser.set_defaults(func=partial(tui_command, run_tui=run_tui))

    return parser


def main(argv: list[str] | None = None, *, run_tui: TuiRunner | None = None) -> int:
    """Entry point for CLI and tests."""
    # Force UTF-8 on stdout/stderr to handle LLM-generated German text (--ai-review).
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    parser = build_parser(run_tui)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
