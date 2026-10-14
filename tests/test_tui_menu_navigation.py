"""All five main-menu actions reach their screens (AR-138, AR-147).

Headless Pilot tests against the target TUI package; every file the screens could touch lives in
tmp_path (working directory) or a patched store path. Structure and navigation only - colours,
spacing and real terminal rendering are not checked here."""

import asyncio

import pytest
from textual.widgets import OptionList

import mcpthreat_scan.policy.reputation as reputation
from mcpthreat_scan.tui.app import MCPScannerApp
from mcpthreat_scan.tui.screens.ignore_manager import IgnoreManagerScreen
from mcpthreat_scan.tui.screens.main_menu import _MENU_ITEMS, MainMenuScreen
from mcpthreat_scan.tui.screens.reputation_manager import ReputationManagerScreen
from mcpthreat_scan.tui.screens.scan_wizard import ScanPathScreen
from mcpthreat_scan.tui.screens.diff_wizard import DiffPathScreen


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-dummy")
    monkeypatch.setattr(reputation, "DEFAULT_STORE_PATH", tmp_path / "reputation.json")


def _select(index):
    async def _run():
        app = MCPScannerApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            assert isinstance(app.screen, MainMenuScreen)
            option_list = app.screen.query_one(OptionList)
            option_list.highlighted = index
            await pilot.press("enter")
            await pilot.pause()
            screen_after = app.screen
            return screen_after, len(app.screen_stack)

    return asyncio.run(_run())


def test_menu_offers_the_five_documented_actions_in_order():
    assert [key for key, _ in _MENU_ITEMS] == ["scan", "diff", "ignore", "reputation", "quit"]


@pytest.mark.parametrize(
    ("index", "screen_class"),
    [(0, ScanPathScreen), (1, DiffPathScreen), (2, IgnoreManagerScreen), (3, ReputationManagerScreen)],
)
def test_menu_action_opens_its_screen_on_top_of_the_menu(index, screen_class):
    screen, stack_depth = _select(index)

    assert type(screen) is screen_class
    assert stack_depth == 3  # default screen, main menu, action screen


def test_diff_action_starts_with_the_before_version_step():
    screen, _ = _select(1)

    assert "Before version" in screen._step_label


def test_quit_action_exits_the_app():
    async def _run():
        app = MCPScannerApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            app.screen.query_one(OptionList).highlighted = 4
            await pilot.press("enter")
            await pilot.pause()
            return app.return_code, app._exit

    return_code, exited = asyncio.run(_run())

    assert exited is True


@pytest.mark.parametrize("index", [0, 1, 2, 3])
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
