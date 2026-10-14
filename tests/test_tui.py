"""Tests for Phase 14 (P14-1 bis P14-5): interaktive TUI.

Uses Textual's own Pilot API for headless interaction tests. Every async test body
runs via asyncio.run() inside a normal sync test function - this avoids the new
dependency pytest-asyncio, which is not installed in the project.
"""

import asyncio
import json
from pathlib import Path

from textual.app import App
from textual.widgets import Checkbox, DataTable, Input, ListView, Static

from mcpthreat_scan.core.exceptions import ReportError
from mcpthreat_scan.tui.app import MCPScannerApp
from mcpthreat_scan.tui.screens.ignore_manager import IgnoreManagerScreen
from mcpthreat_scan.tui.screens.main_menu import MainMenuScreen
from mcpthreat_scan.tui.screens.reputation_manager import ReputationManagerScreen
from mcpthreat_scan.tui.screens.results import ResultsScreen
from mcpthreat_scan.tui.screens.running import RunningScreen
from mcpthreat_scan.tui.screens.scan_wizard import ScanOptionsScreen
from mcpthreat_scan.tui.screens.setup import SetupScreen

_EMPTY_SUMMARY = {"categories_checked": 9, "categories_without_finding": 9, "categories_with_finding": []}


def _fake_report(findings=None):
    findings = findings or []
    return {"target": "x", "findings": findings, "summary": dict(_EMPTY_SUMMARY)}


def test_main_menu_shows_ascii_banner_with_project_info(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-dummy")

    async def _run():
        app = MCPScannerApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            from textual.widgets import Static

            logo = str(app.screen.query_one("#logo", Static).content)
            info = str(app.screen.query_one("#banner-info", Static).content)

            assert "Autorea" in info
            assert "v0.1.0" in info
            assert "github.com/0xtahaa" in info
            # ASCII art does not consist solely of empty lines.
            assert logo.strip() != ""
            await pilot.pause()

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
    # load_dotenv() searches by default starting at the caller's file path (tui/app.py), NOT at
    # os.getcwd() - a plain chdir() would therefore still find the real project .env.
    # For the "no key" case it is therefore additionally mocked as a no-op.
    monkeypatch.setattr("mcpthreat_scan.tui.app.load_dotenv", lambda: None)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    async def _run():
        app = MCPScannerApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            assert isinstance(app.screen, SetupScreen)

    asyncio.run(_run())


def test_setup_screen_skip_button_leads_to_main_menu(monkeypatch, tmp_path):
    monkeypatch.setattr("mcpthreat_scan.tui.app.load_dotenv", lambda: None)
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
    monkeypatch.setattr("mcpthreat_scan.tui.app.load_dotenv", lambda: None)
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
            assert len(list_view.children) == 0

    asyncio.run(_run())

    ignore_content = (tmp_path / ".mcpscannerignore").read_text(encoding="utf-8")
    assert "server.py:Hardcoded Secret" in ignore_content


def test_ignore_manager_shows_entries_and_removes_selected(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".mcpscannerignore").write_text(
        "server.py:Hardcoded Secret\nother.py:Command Injection\n", encoding="utf-8"
    )

    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await app.push_screen(IgnoreManagerScreen())
            await pilot.pause()
            table = app.screen.query_one(DataTable)
            assert table.row_count == 2
            await pilot.press("d")
            await pilot.pause()
            assert table.row_count == 1

    asyncio.run(_run())

    remaining = (tmp_path / ".mcpscannerignore").read_text(encoding="utf-8")
    assert remaining.count("\n") == 1


def test_reputation_manager_shows_entries_and_revokes_selected(monkeypatch, tmp_path):
    store_path = tmp_path / "reputation.json"
    store_path.write_text(
        json.dumps({"example-server": {"version_hash": "abc", "reviewed_at": "2026-01-01"}}),
        encoding="utf-8",
    )
    monkeypatch.setattr("mcpthreat_scan.policy.reputation.DEFAULT_STORE_PATH", store_path)

    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await app.push_screen(ReputationManagerScreen())
            await pilot.pause()
            table = app.screen.query_one(DataTable)
            assert table.row_count == 1
            await pilot.press("d")
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
                if isinstance(app.screen, ResultsScreen):
                    break
                await pilot.pause(0.05)
            assert isinstance(app.screen, ResultsScreen)
            # Extra pause: lets the asynchronous Header._on_mount() callback of the previous
            # screen (ScanOptionsScreen), already removed via pop_screen(), finish cleanly
            # before run_test() shuts down when leaving the context - otherwise an
            # occasional Textual-internal NoMatches at shutdown (timing race in Header
            # itself, not in our code).
            await pilot.pause(0.1)

    asyncio.run(_run())
    assert calls == [(target, True)]


def test_running_screen_runs_real_scan_and_shows_results():
    """Real integration test: RunningScreen actually calls run_scan() in a
    worker thread (no mock), analogous to the end-to-end tests in test_cli.py."""
    from mcpthreat_scan.core.orchestrator import run_scan

    def _results_ready(screen):
        # The screen type alone is not enough: ListView and its entries are only mounted after
        # the switch (race between assertion and mount).
        if not isinstance(screen, ResultsScreen):
            return False
        list_views = list(screen.query(ListView))
        return bool(list_views) and len(list_views[0].children) >= 1

    async def _run():
        app = App()
        async with app.run_test() as pilot:
            task = lambda: run_scan("benchmark/vulnerable/command_injection.py")
            await app.push_screen(RunningScreen(task, "Scanne..."))

            for _ in range(200):
                if _results_ready(app.screen):
                    break
                await pilot.pause(0.1)

            assert isinstance(app.screen, ResultsScreen)
            list_view = app.screen.query_one(ListView)
            assert len(list_view.children) >= 1
            # First let the screen's messages be processed, then the safeguard against the
            # Header-internal timing race at shutdown (see test_scan_options_screen_...).
            await pilot.pause()
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


def test_results_screen_colors_severity_markup_with_theme_color():
    from mcpthreat_scan.tui.screens.results import _severity_markup
    from mcpthreat_scan.tui.theme import SEVERITY_COLORS

    markup = _severity_markup("ERROR")
    assert SEVERITY_COLORS["ERROR"] in markup
    assert "Critical" in markup


def test_results_screen_shows_findings_as_stacked_cards_not_wide_table(monkeypatch, tmp_path):
    """Covers the case reported by the human: long messages must no longer disappear in
    a wide table row, but are shown as a stacked card
    (severity/category, location, message each on its own line)."""
    monkeypatch.chdir(tmp_path)
    report = _fake_report(
        [{
            "category": "Missing Audit Logging",
            "file": "server.py",
            "line": 12,
            "severity": "WARNING",
            "message": "A very long example message that would be truncated in a narrow table column "
            "but is meant to be fully readable here as its own paragraph.",
        }]
    )

    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await app.push_screen(ResultsScreen(report))
            await pilot.pause()
            item = app.screen.query_one(ListView).children[0]
            texts = [child.content for child in item.query(Static)]
            assert any("Missing Audit Logging" in str(t) for t in texts)
            assert any("server.py:12" in str(t) for t in texts)
            assert any("fully readable here as its own paragraph" in str(t) for t in texts)

    asyncio.run(_run())


def test_scan_path_screen_input_field_accepts_typed_path(tmp_path):
    """Covers the case reported by the human: make a path outside the scanner folder
    (or outside the tree start root) reachable via the input field."""
    from mcpthreat_scan.tui.screens.scan_wizard import ScanPathScreen

    target_dir = tmp_path / "irgendein-mcp-server"
    target_dir.mkdir()

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

    def fake_build_diff_report(before, after):
        calls.append((before, after))
        return _fake_report()

    monkeypatch.setattr("mcpthreat_scan.tui.screens.diff_wizard.run_diff", fake_build_diff_report)

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
                if isinstance(app.screen, ResultsScreen):
                    break
                await pilot.pause(0.05)
            assert isinstance(app.screen, ResultsScreen)

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
