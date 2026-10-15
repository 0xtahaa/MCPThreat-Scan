"""All six main-menu actions reach their screens (AR-138, AR-147).

Headless Pilot tests against the target TUI package; every file the screens could touch lives in
tmp_path (working directory) or a patched store path. Structure and navigation only - colours,
spacing and real terminal rendering are not checked here."""

import asyncio
from datetime import datetime

import pytest
from textual.widgets import OptionList, Static

import mcpthreat_scan.policy.reputation as reputation
from mcpthreat_scan.tui.app import MCPScannerApp
from mcpthreat_scan.tui.screens.main_menu import _MENU_ITEMS, SHORTCUTS_LINE, MainMenuScreen
from mcpthreat_scan.tui.screens.results import ResultsScreen
from mcpthreat_scan.tui.screens.scan_wizard import ScanPathScreen
from mcpthreat_scan.tui.screens.settings import SettingsScreen
from mcpthreat_scan.tui.screens.trust import TrustScreen
from mcpthreat_scan.tui.screens.diff_wizard import DiffPathScreen

_REPORT = {
    "target": "srv",
    "findings": [{"category": "Tool Poisoning", "file": "a.py", "line": 3, "severity": "ERROR", "message": "m"}],
    "summary": {"categories_checked": 9, "categories_without_finding": 8, "categories_with_finding": ["Tool Poisoning"]},
}


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-dummy")
    monkeypatch.setattr(reputation, "DEFAULT_STORE_PATH", tmp_path / "reputation.json")


def _select(index, prepare=None):
    async def _run():
        app = MCPScannerApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            assert isinstance(app.screen, MainMenuScreen)
            if prepare:
                prepare(app)
                app.screen._refresh()
            option_list = app.screen.query_one(OptionList)
            option_list.highlighted = index
            await pilot.press("enter")
            await pilot.pause()
            screen_after = app.screen
            return screen_after, len(app.screen_stack)

    return asyncio.run(_run())


def _menu_state(prepare=None):
    """(workspace text, 'View Findings' disabled?) after an optional state setup."""
    async def _run():
        app = MCPScannerApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            if prepare:
                prepare(app)
                app.screen._refresh()
                await pilot.pause()
            workspace = str(app.screen.query_one("#workspace", Static).content)
            disabled = app.screen.query_one(OptionList).get_option("findings").disabled
            return workspace, disabled

    return asyncio.run(_run())


def _press(key):
    async def _run():
        app = MCPScannerApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press(key)
            await pilot.pause()
            return type(app.screen), app._exit

    return asyncio.run(_run())


def test_menu_offers_the_six_documented_actions_in_order():
    assert [key for key, _ in _MENU_ITEMS] == ["scan", "diff", "findings", "trust", "settings", "quit"]


@pytest.mark.parametrize(
    ("index", "screen_class"),
    [(0, ScanPathScreen), (1, DiffPathScreen), (3, TrustScreen), (4, SettingsScreen)],
)
def test_menu_action_opens_its_screen_on_top_of_the_menu(index, screen_class):
    screen, stack_depth = _select(index)

    assert type(screen) is screen_class
    assert stack_depth == 3  # default screen, main menu, action screen


def test_diff_action_starts_with_the_baseline_step():
    screen, _ = _select(1)

    assert "Select baseline" in screen._step_label


def test_quit_action_exits_the_app():
    async def _run():
        app = MCPScannerApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            app.screen.query_one(OptionList).highlighted = 5
            await pilot.press("enter")
            await pilot.pause()
            return app.return_code, app._exit

    return_code, exited = asyncio.run(_run())

    assert exited is True


def test_view_findings_is_disabled_without_results_and_selecting_it_does_nothing():
    _, disabled = _menu_state()
    screen, stack_depth = _select(2)

    assert disabled is True
    assert type(screen) is MainMenuScreen and stack_depth == 2


def test_view_findings_is_enabled_and_opens_the_last_report_once_results_exist():
    def prepare(app):
        app.last_report = _REPORT

    _, disabled = _menu_state(prepare)
    screen, stack_depth = _select(2, prepare)

    assert disabled is False
    assert type(screen) is ResultsScreen and stack_depth == 3


def test_workspace_shows_empty_state_without_inventing_values():
    workspace, _ = _menu_state()

    assert "none selected" in workspace
    assert "none yet" in workspace
    assert "none (run a scan first)" in workspace


def test_workspace_shows_the_real_app_state(tmp_path):
    def prepare(app):
        app.current_target = tmp_path / "server"
        app.last_run = {"kind": "scan", "status": "completed", "finished_at": datetime(2026, 10, 15, 14, 30)}
        app.last_report = _REPORT

    workspace, _ = _menu_state(prepare)

    # long paths are shortened from the left: the project folder at the end stays visible
    assert workspace.splitlines()[0].rstrip().endswith("server")
    assert "scan completed" in workspace
    assert "2026-10-15 14:30" in workspace
    assert "1 finding(s) available" in workspace


@pytest.mark.parametrize(
    ("key", "screen_class"),
    [("s", ScanPathScreen), ("d", DiffPathScreen), ("question_mark", SettingsScreen)],
)
def test_shortcut_line_keys_open_what_it_promises(key, screen_class):
    screen_type, _ = _press(key)

    assert screen_type is screen_class


def test_shortcut_q_quits_and_the_line_lists_exactly_the_bound_keys():
    _, exited = _press("q")

    assert exited is True
    assert "S Scan" in SHORTCUTS_LINE and "D Diff" in SHORTCUTS_LINE
    assert "? Help" in SHORTCUTS_LINE and "Q Quit" in SHORTCUTS_LINE
    assert {binding.key for binding in MainMenuScreen.BINDINGS} == {"s", "d", "question_mark", "q"}


@pytest.mark.parametrize("index", [0, 1, 3, 4])
def test_escape_returns_from_every_action_screen_to_the_menu(index):
    async def _run():
        app = MCPScannerApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            app.screen.query_one(OptionList).highlighted = index
            await pilot.press("enter")
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            return type(app.screen)

    assert asyncio.run(_run()) is MainMenuScreen
