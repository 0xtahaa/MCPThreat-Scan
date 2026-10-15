"""Tests for Phase 14 (P14-1 bis P14-5): interaktive TUI.

Uses Textual's own Pilot API for headless interaction tests. Every async test body
runs via asyncio.run() inside a normal sync test function - this avoids the new
dependency pytest-asyncio, which is not installed in the project.
"""

import asyncio
import importlib.metadata
import json
import os
from pathlib import Path

from textual.app import App
from textual.widgets import Checkbox, DataTable, Input, ListView, Static

from mcpthreat_scan.core.exceptions import ReportError
from mcpthreat_scan.tui.app import MCPScannerApp
from mcpthreat_scan.tui.screens.comparison import ComparisonScreen
from mcpthreat_scan.tui.screens.main_menu import MainMenuScreen
from mcpthreat_scan.tui.screens.results import ResultsScreen
from mcpthreat_scan.tui.screens.running import RunningScreen
from mcpthreat_scan.tui.screens.scan_wizard import ScanOptionsScreen
from mcpthreat_scan.tui.screens.setup import SetupScreen
from mcpthreat_scan.tui.screens.summary import ScanSummaryScreen
from mcpthreat_scan.tui.screens.trust import TrustScreen

_EMPTY_SUMMARY = {"categories_checked": 9, "categories_without_finding": 9, "categories_with_finding": []}


def _fake_report(findings=None):
    findings = findings or []
    return {"target": "x", "findings": findings, "summary": dict(_EMPTY_SUMMARY)}


def test_main_menu_shows_mark_and_ascii_wordmark_in_a_wide_terminal(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-dummy")

    async def _run():
        app = MCPScannerApp()
        async with app.run_test(size=(110, 36)) as pilot:
            await pilot.pause()
            screen = app.screen
            wordmark = str(screen.query_one("#wordmark", Static).content)

            assert len(wordmark.splitlines()) == 5  # four lines of lettering + info line, as high as the mark
            assert "|_|  |_|" in wordmark  # the figlet "M" of MCPThreat-Scan
            info = wordmark.splitlines()[-1]
            assert "AUTOREA" in info and "Zero-Execution Static Analysis" in info
            assert f"v{importlib.metadata.version('mcpthreat-scan')}" in info and "Status: READY" in info
            assert screen.query_one("#wordmark").display and screen.query_one("#brand-mark").display
            assert not screen.query_one("#app-header").display
            mark = str(screen.query_one("#brand-mark", Static).content)
            braille = {chr(code) for code in range(0x2800, 0x2900)}
            assert len(mark.splitlines()) == 5 and set(mark.replace("\n", "")) <= braille
            # nothing of the lettering is cut off
            assert screen.query_one("#wordmark").size.width >= max(len(line) for line in wordmark.splitlines())

    asyncio.run(_run())


def test_main_menu_falls_back_to_the_compact_header_in_a_narrow_terminal(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-dummy")

    async def _run():
        app = MCPScannerApp()
        async with app.run_test(size=(60, 30)) as pilot:
            await pilot.pause()
            screen = app.screen
            header = str(screen.query_one("#app-header", Static).content)

            assert "AUTOREA / MCP THREAT SCAN" in header
            assert "Zero-Execution Static Analysis" in header
            assert f"Version: v{importlib.metadata.version('mcpthreat-scan')}" in header
            assert "Status: READY" in header
            assert len(header.splitlines()) == 3
            assert screen.query_one("#app-header").display and screen.query_one("#brand-mark").display
            assert not screen.query_one("#wordmark").display

    asyncio.run(_run())


def test_main_menu_drops_only_the_mark_when_the_lettering_just_fits(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-dummy")

    async def _run():
        app = MCPScannerApp()
        async with app.run_test(size=(72, 30)) as pilot:
            await pilot.pause()
            screen = app.screen

            assert screen.query_one("#wordmark").display
            assert not screen.query_one("#brand-mark").display
            assert not screen.query_one("#app-header").display

    asyncio.run(_run())


def test_app_shows_main_menu_when_api_key_present(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-dummy")

    async def _run():
        app = MCPScannerApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            assert isinstance(app.screen, MainMenuScreen)

    asyncio.run(_run())


def test_app_shows_setup_screen_when_api_key_missing(monkeypatch, tmp_path):
    # The app reads the .env of the working directory (and its parents). For the "no key" case
    # load_dotenv is additionally mocked as a no-op so no stray .env above tmp_path can interfere.
    monkeypatch.setattr("mcpthreat_scan.tui.app.load_dotenv", lambda *args, **kwargs: None)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    async def _run():
        app = MCPScannerApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            assert isinstance(app.screen, SetupScreen)

    asyncio.run(_run())


def test_setup_screen_skip_button_leads_to_main_menu(monkeypatch, tmp_path):
    monkeypatch.setattr("mcpthreat_scan.tui.app.load_dotenv", lambda *args, **kwargs: None)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    async def _run():
        app = MCPScannerApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.click("#skip")
            await pilot.pause()
            assert isinstance(app.screen, MainMenuScreen)
            assert not (tmp_path / ".env").exists()

    asyncio.run(_run())


def test_setup_screen_save_writes_env_file_and_sets_environ(monkeypatch, tmp_path):
    monkeypatch.setattr("mcpthreat_scan.tui.app.load_dotenv", lambda *args, **kwargs: None)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    async def _run():
        app = MCPScannerApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            input_widget = app.screen.query_one("#key-input", Input)
            input_widget.value = "sk-test-dummy-value"
            await pilot.click("#save")
            await pilot.pause()
            assert isinstance(app.screen, MainMenuScreen)

    asyncio.run(_run())

    import os

    env_content = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "sk-test-dummy-value" in env_content
    assert os.environ.get("OPENAI_API_KEY") == "sk-test-dummy-value"


def test_main_menu_quit_binding_exits_app(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-dummy")

    async def _run():
        app = MCPScannerApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("q")
            await pilot.pause()

        assert not app.is_running

    asyncio.run(_run())


def test_results_screen_ignore_action_writes_mcpscannerignore(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    report = _fake_report(
        [{"category": "Hardcoded Secret", "file": "server.py", "line": 6, "severity": "ERROR", "message": "x"}]
    )

    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await app.push_screen(ResultsScreen(report))
            await pilot.pause()
            list_view = app.screen.query_one(ListView)
            assert len(list_view.children) == 1
            await pilot.press("i")
            await pilot.pause()
            assert len(list_view.children) == 1  # nothing happens before the confirmation
            await pilot.press("y")
            await pilot.pause()
            assert len(list_view.children) == 0

    asyncio.run(_run())

    ignore_content = (tmp_path / ".mcpscannerignore").read_text(encoding="utf-8")
    assert "server.py:Hardcoded Secret" in ignore_content


def test_trust_screen_shows_exclusions_and_removes_the_selected_one_after_confirmation(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("mcpthreat_scan.policy.reputation.DEFAULT_STORE_PATH", tmp_path / "reputation.json")
    (tmp_path / ".mcpscannerignore").write_text(
        "server.py:Hardcoded Secret\nother.py:Command Injection\n", encoding="utf-8"
    )

    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await app.push_screen(TrustScreen())
            await pilot.pause()
            table = app.screen.query_one("#exclusions-table", DataTable)
            assert table.row_count == 2
            table.focus()
            await pilot.press("d")
            await pilot.pause()
            assert table.row_count == 2  # asks first
            await pilot.press("y")
            await pilot.pause()
            assert table.row_count == 1

    asyncio.run(_run())

    remaining = (tmp_path / ".mcpscannerignore").read_text(encoding="utf-8")
    assert remaining.count("\n") == 1


def test_trust_screen_shows_trusted_servers_and_revokes_the_selected_one_after_confirmation(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    store_path = tmp_path / "reputation.json"
    store_path.write_text(
        json.dumps({"example-server": {"version_hash": "abc", "reviewed_at": "2026-01-01"}}),
        encoding="utf-8",
    )
    monkeypatch.setattr("mcpthreat_scan.policy.reputation.DEFAULT_STORE_PATH", store_path)

    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await app.push_screen(TrustScreen())
            await pilot.pause()
            table = app.screen.query_one("#trusted-table", DataTable)
            assert table.row_count == 1
            await pilot.press("d")
            await pilot.pause()
            assert table.row_count == 1  # asks first
            await pilot.press("y")
            await pilot.pause()
            assert table.row_count == 0

    asyncio.run(_run())

    assert json.loads(store_path.read_text(encoding="utf-8")) == {}


def test_scan_options_screen_passes_target_and_ai_review_flag(monkeypatch, tmp_path):
    calls = []

    def fake_build_report(path, *, ai_review=False, ignore_file=".mcpscannerignore"):
        calls.append((path, ai_review))
        return _fake_report()

    monkeypatch.setattr("mcpthreat_scan.tui.screens.scan_wizard.run_scan", fake_build_report)
    target = tmp_path / "server.py"
    target.write_text("def handler():\n    pass\n", encoding="utf-8")

    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await app.push_screen(ScanOptionsScreen(target))
            await pilot.pause()
            app.screen.query_one("#ai-review", Checkbox).value = True
            await pilot.click("#start")

            for _ in range(50):
                if isinstance(app.screen, ScanSummaryScreen):
                    break
                await pilot.pause(0.05)
            assert isinstance(app.screen, ScanSummaryScreen)
            # Extra pause: lets the asynchronous Header._on_mount() callback of the previous
            # screen (ScanOptionsScreen), already removed via pop_screen(), finish cleanly
            # before run_test() shuts down when leaving the context - otherwise an
            # occasional Textual-internal NoMatches at shutdown (timing race in Header
            # itself, not in our code).
            await pilot.pause(0.1)

    asyncio.run(_run())
    assert calls == [(target, True)]


def test_running_screen_runs_real_scan_and_shows_summary_then_findings():
    """Real integration test: RunningScreen actually calls run_scan() in a
    worker thread (no mock), analogous to the end-to-end tests in test_cli.py."""
    from mcpthreat_scan.core.orchestrator import run_scan

    async def _run():
        app = App()
        async with app.run_test() as pilot:
            task = lambda progress=None: run_scan("benchmark/vulnerable/command_injection.py", progress=progress)
            await app.push_screen(RunningScreen(task, "Scanne..."))

            for _ in range(200):
                if isinstance(app.screen, ScanSummaryScreen):
                    break
                await pilot.pause(0.1)
            assert isinstance(app.screen, ScanSummaryScreen)
            await pilot.pause()

            card = str(app.screen.query_one("#summary-card", Static).content)
            assert "Completed" in card and "Total findings" in card and "HIGH" in card

            await pilot.press("f")
            for _ in range(50):
                if isinstance(app.screen, ResultsScreen) and app.screen.query(ListView):
                    break
                await pilot.pause(0.1)
            assert isinstance(app.screen, ResultsScreen)
            await pilot.pause(0.2)
            assert len(app.screen.query_one(ListView).children) >= 1
            await pilot.pause(0.1)

    asyncio.run(_run())


def test_app_registers_and_activates_custom_theme(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-dummy")

    async def _run():
        app = MCPScannerApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app.theme == "mcp-scanner"
            assert "mcp-scanner" in app.available_themes

    asyncio.run(_run())


def test_severity_label_is_colored_with_the_theme_color():
    from mcpthreat_scan.tui.display import severity_text
    from mcpthreat_scan.tui.theme import SEVERITY_COLORS

    label = severity_text("ERROR")

    assert label.plain == "HIGH"
    assert SEVERITY_COLORS["ERROR"] in str(label.style)


def test_results_screen_shows_a_compact_row_and_the_full_finding_in_the_detail_panel(monkeypatch, tmp_path):
    """Long messages must not disappear in a row: the list stays one line per finding, the detail
    panel shows category, severity, location, description, rule, evidence and recommendation."""
    monkeypatch.chdir(tmp_path)
    report = _fake_report(
        [{
            "category": "Missing Audit Logging",
            "file": "server.py",
            "line": 12,
            "severity": "WARNING",
            "message": "A very long example message that would be truncated in a narrow table column "
            "but is meant to be fully readable here as its own paragraph.",
            "rule_id": "missing-audit",
            "evidence": "def handler(x):",
        }]
    )

    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await app.push_screen(ResultsScreen(report))
            await pilot.pause()
            row = str(app.screen.query_one(ListView).children[0].query_one(Static).content)
            detail = str(app.screen.query_one("#detail", Static).content)
            assert "MEDIUM" in row and "Missing Audit Logging" in row and "server.py:12" in row
            assert "fully readable here as its own paragraph" in detail
            assert "missing-audit" in detail and "def handler(x):" in detail
            assert "Recommendation" in detail and "Log every tool invocation" in detail

    asyncio.run(_run())


def test_scan_path_screen_input_field_accepts_typed_path(tmp_path):
    """Covers the case reported by the human: make a path outside the scanner folder
    (or outside the tree start root) reachable via the input field."""
    from mcpthreat_scan.tui.screens.scan_wizard import ScanPathScreen

    target_dir = tmp_path / "irgendein-mcp-server"
    target_dir.mkdir()
    (target_dir / "server.py").write_text("def handler():\n    pass\n", encoding="utf-8")

    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await app.push_screen(ScanPathScreen())
            await pilot.pause()
            input_widget = app.screen.query_one("#path-input", Input)
            input_widget.value = str(target_dir)
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, ScanOptionsScreen)
            assert app.screen._target_path == target_dir

    asyncio.run(_run())


def test_scan_path_screen_input_field_rejects_missing_path(tmp_path):
    from mcpthreat_scan.tui.screens.scan_wizard import ScanPathScreen

    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await app.push_screen(ScanPathScreen())
            await pilot.pause()
            input_widget = app.screen.query_one("#path-input", Input)
            input_widget.value = str(tmp_path / "does-not-exist")
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, ScanPathScreen)

    asyncio.run(_run())


def test_diff_path_screen_input_field_accepts_typed_path(tmp_path):
    from mcpthreat_scan.tui.screens.diff_wizard import DiffPathScreen

    target_file = tmp_path / "server.py"
    target_file.write_text("def handler():\n    pass\n", encoding="utf-8")
    chosen = []

    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await app.push_screen(DiffPathScreen("Testschritt", chosen.append))
            await pilot.pause()
            input_widget = app.screen.query_one("#path-input", Input)
            input_widget.value = str(target_file)
            await pilot.press("enter")
            await pilot.pause()

    asyncio.run(_run())
    assert chosen == [target_file]


def test_diff_wizard_chains_two_file_picks_and_calls_build_diff_report(monkeypatch):
    """Tests the chaining of open_diff_wizard() directly via the selection callbacks
    instead of simulated DirectoryTree key presses (tree navigation is Textual's own,
    already tested functionality - only our own chaining logic matters here)."""
    from mcpthreat_scan.tui.screens.diff_wizard import DiffPathScreen, open_diff_wizard

    calls = []

    comparison = {
        "mode": "files", "before": "before.py", "after": "after.py",
        "files": {"added": [], "removed": [], "modified": ["after.py"]},
        "tool_changes": [], "new_findings": [], "resolved_findings": [], "unchanged_count": 0,
    }

    def fake_comparison(before, after):
        calls.append((before, after))
        return comparison

    monkeypatch.setattr("mcpthreat_scan.tui.screens.diff_wizard.run_version_comparison", fake_comparison)

    async def _run():
        app = App()
        async with app.run_test() as pilot:
            open_diff_wizard(app)
            await pilot.pause()
            assert isinstance(app.screen, DiffPathScreen)

            app.screen._on_chosen(Path("before.py"))
            await pilot.pause()
            assert isinstance(app.screen, DiffPathScreen)

            app.screen._on_chosen(Path("after.py"))

            for _ in range(50):
                if isinstance(app.screen, ComparisonScreen):
                    break
                await pilot.pause(0.05)
            assert isinstance(app.screen, ComparisonScreen)

    asyncio.run(_run())
    assert calls == [(Path("before.py"), Path("after.py"))]


def test_running_screen_handles_report_error_without_crashing():
    def failing_task():
        raise ReportError("Test error")

    async def _run():
        app = App()
        async with app.run_test() as pilot:
            screens_before = len(app.screen_stack)
            await app.push_screen(RunningScreen(failing_task, "Scanne..."))

            for _ in range(50):
                if len(app.screen_stack) == screens_before:
                    break
                await pilot.pause(0.05)

            assert len(app.screen_stack) == screens_before

    asyncio.run(_run())


def test_running_screen_survives_an_unexpected_exception():
    """A non-ReportError failure in the worker must be reported, not crash the whole app."""

    def crashing_task():
        raise RuntimeError("unexpected")

    async def _run():
        app = App()
        async with app.run_test() as pilot:
            screens_before = len(app.screen_stack)
            await app.push_screen(RunningScreen(crashing_task, "Scanne..."))

            for _ in range(50):
                if any("Unexpected error (RuntimeError)" in n.message for n in app._notifications):
                    break
                await pilot.pause(0.05)

            assert any("Unexpected error (RuntimeError)" in n.message for n in app._notifications)
            assert len(app.screen_stack) == screens_before
            assert app.is_running

    asyncio.run(_run())


def test_app_loads_api_key_from_env_file_in_working_directory(monkeypatch, tmp_path):
    """The setup screen writes ./.env, so the next start must read exactly that file."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "placeholder")
    monkeypatch.delenv("OPENAI_API_KEY")  # records the original state so the app's change is undone
    (tmp_path / ".env").write_text("OPENAI_API_KEY=sk-test-from-cwd\n", encoding="utf-8")

    async def _run():
        app = MCPScannerApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            assert isinstance(app.screen, MainMenuScreen)
            assert os.environ["OPENAI_API_KEY"] == "sk-test-from-cwd"

    asyncio.run(_run())
