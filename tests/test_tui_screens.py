"""Behaviour tests for the redesigned TUI screens: scan workflow and workspace state, summary,
findings filter/detail, export, version comparison, trusted servers & exclusions, settings.

Headless Pilot tests. Scanner calls are replaced by small fakes except where a real scan is the
point; every file the screens write lives in tmp_path."""

import asyncio
import json
import threading
from pathlib import Path

import pytest
from textual.app import App
from textual.widgets import DataTable, Input, ListView, OptionList, Static

import mcpthreat_scan.policy.reputation as reputation
from mcpthreat_scan.core.exceptions import ReportError
from mcpthreat_scan.reporting.json import render_json
from mcpthreat_scan.tui.app import MCPScannerApp
from mcpthreat_scan.tui.display import display_path, format_duration, location, shorten_left
from mcpthreat_scan.tui.screens.comparison import ComparisonScreen
from mcpthreat_scan.tui.screens.confirm import ConfirmScreen
from mcpthreat_scan.tui.screens.diff_wizard import DiffPathScreen
from mcpthreat_scan.tui.screens.export import ExportScreen
from mcpthreat_scan.tui.screens.main_menu import MainMenuScreen
from mcpthreat_scan.tui.screens.results import ResultsScreen
from mcpthreat_scan.tui.screens.running import RunningScreen
from mcpthreat_scan.tui.screens.scan_wizard import ScanOptionsScreen, ScanPathScreen, validate_target
from mcpthreat_scan.tui.screens.settings import SettingsScreen
from mcpthreat_scan.tui.screens.setup import SetupScreen
from mcpthreat_scan.tui.screens.summary import ScanSummaryScreen
from mcpthreat_scan.tui.screens.trust import IgnoreRuleScreen, TrustScreen

SUMMARY = {"categories_checked": 9, "categories_without_finding": 8, "categories_with_finding": []}


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-dummy")
    monkeypatch.setattr(reputation, "DEFAULT_STORE_PATH", tmp_path / "reputation.json")


def _finding(category="Command Injection", severity="ERROR", file="a.py", line=3, **extra):
    row = {"category": category, "file": file, "line": line, "severity": severity, "message": "msg",
           "rule_id": "rule-x", "evidence": None}
    return {**row, **extra}


def _report(*findings, **summary):
    return {"target": "srv", "findings": list(findings), "summary": {**SUMMARY, **summary}}


def _note():
    return _finding("Scan Coverage", "INFO", "big.ts", None, rule_id="ts-not-analyzed")


async def _until(pilot, predicate, tries=100):
    for _ in range(tries):
        if predicate():
            # Let the Header of a freshly pushed screen finish mounting before the test can end
            # (known Textual timing race, see the comment in tests/test_tui.py).
            await pilot.pause(0.15)
            return
        await pilot.pause(0.05)
    raise AssertionError("condition not reached")


def _text(widget):
    return str(widget.content)


# ---------------------------------------------------------------- display helpers and validation


def test_display_helpers_keep_the_informative_end_and_relative_paths(tmp_path):
    assert shorten_left("C:\\a\\b\\c\\project", 12).startswith("…") and shorten_left("C:\\a\\b\\c\\project", 12).endswith("project")
    assert shorten_left("short", 40) == "short"
    inside = tmp_path / "tools" / "mail.py"
    assert display_path(str(inside), str(tmp_path)) == "tools/mail.py"
    assert display_path("elsewhere/x.py", str(tmp_path)) == "elsewhere/x.py"
    assert display_path("x.py", "a.py -> b.py") == "x.py"
    assert location({"file": "x.py", "line": 7}, None) == "x.py:7"
    assert location({"file": "x.py", "line": None}, None) == "x.py"
    assert format_duration(4.25) == "4.2 s" and format_duration(125) == "2 min 05 s"


def test_validate_target_explains_why_a_target_is_not_accepted(tmp_path):
    (tmp_path / "empty").mkdir()
    (tmp_path / "notes.txt").write_text("x", encoding="utf-8")
    (tmp_path / "ok").mkdir()
    (tmp_path / "ok" / "server.py").write_text("x = 1\n", encoding="utf-8")

    assert "not found" in validate_target(tmp_path / "missing")[0]
    assert "No Python or TypeScript" in validate_target(tmp_path / "empty")[0]
    assert "Unsupported file type" in validate_target(tmp_path / "notes.txt")[0]
    assert validate_target(tmp_path / "ok") == (None, 1)
    assert validate_target(tmp_path / "ok" / "server.py") == (None, 1)


# ---------------------------------------------------------------- scan workflow and workspace state


def _fake_scan(report, calls=None):
    def fake(path, *, ai_review=False, progress=None, ignore_file=".mcpscannerignore"):
        if calls is not None:
            calls.append((Path(path), ai_review))
        if progress:
            progress("Static rules (Semgrep)")
        if isinstance(report, Exception):
            raise report
        return report

    return fake


def _scan_through_wizard(monkeypatch, tmp_path, report, after_summary):
    server = tmp_path / "srv"
    server.mkdir()
    (server / "server.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr("mcpthreat_scan.tui.screens.scan_wizard.run_scan", _fake_scan(report))

    async def _run():
        app = MCPScannerApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("s")
            await pilot.pause()
            app.screen.query_one(Input).value = str(server)
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, ScanOptionsScreen)
            await pilot.press("enter")  # the Start button has the focus
            return await after_summary(app, pilot, server)

    return asyncio.run(_run())


def test_a_finished_scan_fills_the_workspace_and_unlocks_view_findings(monkeypatch, tmp_path):
    report = _report(_finding(), _finding("Hardcoded Secret", "ERROR", "b.py", 9))

    async def after(app, pilot, server):
        await _until(pilot, lambda: isinstance(app.screen, ScanSummaryScreen))
        await pilot.pause()
        run = app.last_run
        await pilot.press("escape")  # main menu, not the wizard screens below the summary
        await pilot.pause()
        menu = app.screen
        return (
            type(menu), len(app.screen_stack), run, app.last_report, app.current_target,
            _text(menu.query_one("#workspace", Static)),
            menu.query_one(OptionList).get_option("findings").disabled,
        )

    menu_type, depth, run, last_report, target, workspace, findings_disabled = _scan_through_wizard(
        monkeypatch, tmp_path, report, after
    )

    assert menu_type is MainMenuScreen and depth == 2
    assert (run["kind"], run["status"], run["error"], run["ai_review"]) == ("scan", "completed", None, False)
    assert run["duration_s"] >= 0 and run["finished_at"] is not None
    assert last_report == report and target == tmp_path / "srv"
    assert "scan completed" in workspace and "2 finding(s) available" in workspace
    assert findings_disabled is False


def test_a_failed_scan_is_recorded_as_failed_and_keeps_the_previous_results(monkeypatch, tmp_path):
    async def after(app, pilot, server):
        await _until(pilot, lambda: app.last_run is not None)
        await pilot.pause(0.2)
        messages = [n.message for n in app._notifications]
        return app.last_run, app.last_report, messages, type(app.screen)

    run, last_report, messages, screen = _scan_through_wizard(
        monkeypatch, tmp_path, ReportError("Semgrep error: boom"), after
    )

    assert (run["kind"], run["status"]) == ("scan", "failed")
    assert "Semgrep error: boom" in run["error"]
    assert last_report is None
    assert any("Semgrep error: boom" in m for m in messages)
    assert screen is ScanOptionsScreen  # the user can go back or start again


def test_scan_path_screen_rejects_an_empty_folder_with_a_reason(tmp_path):
    (tmp_path / "empty").mkdir()

    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await app.push_screen(ScanPathScreen())
            await pilot.pause()
            app.screen.query_one("#path-input", Input).value = str(tmp_path / "empty")
            await pilot.press("enter")
            await pilot.pause()
            return type(app.screen), _text(app.screen.query_one("#path-status", Static))

    screen, status = asyncio.run(_run())

    assert screen is ScanPathScreen
    assert "No Python or TypeScript" in status


def test_confirm_screen_shows_the_target_and_the_file_count(tmp_path):
    (tmp_path / "srv").mkdir()
    (tmp_path / "srv" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "srv" / "b.ts").write_text("export {}\n", encoding="utf-8")

    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await app.push_screen(ScanOptionsScreen(tmp_path / "srv"))
            await pilot.pause()
            return _text(app.screen.query_one("#target-details", Static))

    details = asyncio.run(_run())

    assert str(tmp_path / "srv") in details and "folder" in details and "2 source file(s)" in details
    assert "never executed" in details


def test_running_screen_shows_phase_files_and_elapsed_time_from_the_engine():
    release = threading.Event()

    def task(progress=None):
        progress("Static rules (Semgrep)")
        progress("Dependency check")
        release.wait(5)
        return _report()

    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await app.push_screen(RunningScreen(task, "Scanning ...", kind="other", target="C:\\srv", files_in_scope=7))
            await _until(pilot, lambda: "Dependency check" in _text(app.screen.query_one("#progress", Static)))
            shown = _text(app.screen.query_one("#progress", Static))
            note = _text(app.screen.query_one("#cancel-note", Static))
            release.set()
            await _until(pilot, lambda: isinstance(app.screen, ResultsScreen))
            return shown, note

    shown, note = asyncio.run(_run())

    assert "Phase" in shown and "Dependency check" in shown and "✓ Static rules (Semgrep)" in shown
    assert "7 source file(s)" in shown and "Elapsed" in shown and "Running" in shown
    assert "cannot be cancelled" in note


# ---------------------------------------------------------------- scan summary


def _summary_card(report, **kwargs):
    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await app.push_screen(ScanSummaryScreen(report, duration_s=kwargs.get("duration_s", 2.5),
                                                    ai_review=kwargs.get("ai_review", False), files_in_scope=kwargs.get("files")))
            await pilot.pause()
            option = app.screen.query_one(OptionList).get_option("findings")
            return _text(app.screen.query_one("#summary-card", Static)), option.disabled

    return asyncio.run(_run())


def test_summary_counts_findings_by_severity_and_keeps_scanner_notes_apart():
    report = _report(_finding(), _finding(severity="WARNING"), _finding(severity="WARNING"),
                     _finding("Missing Audit Logging", "INFO"), _note(), suppressed_count=3)

    card, findings_disabled = _summary_card(report, ai_review=True, files=12)

    assert "Completed" in card and "12 source file(s)" in card and "2.5 s" in card and "AI review" in card
    assert "Total findings  4" in card  # the scanner note is not a security finding
    assert "HIGH" in card and "MEDIUM" in card and "INFO" in card
    assert "Scanner notes   1" in card and "not security findings" in card
    assert "3 finding(s) hidden by ignore rules" in card
    assert findings_disabled is False


def test_summary_of_a_clean_scan_does_not_claim_the_server_is_safe():
    card, findings_disabled = _summary_card(_report())

    assert "Total findings  0" in card
    assert "does not prove the server is safe" in card
    assert findings_disabled is True


# ---------------------------------------------------------------- findings screen


def _results(report, keys=(), wait=0.2):
    """Open the findings screen, press keys, return (row texts, detail text, filter bar)."""
    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await app.push_screen(ResultsScreen(report))
            await pilot.pause()
            for key in keys:
                await pilot.press(key)
                await pilot.pause(wait)
            rows = [_text(item.query_one(Static)) for item in app.screen.query_one(ListView).children]
            return rows, _text(app.screen.query_one("#detail", Static)), _text(app.screen.query_one("#filter-bar", Static))

    return asyncio.run(_run())


def test_findings_are_sorted_by_severity_and_the_filter_cycles_through_all_views():
    report = _report(
        _finding("Missing Audit Logging", "INFO", "c.py", 1),
        _finding(severity="WARNING", file="b.py"),
        _finding(file="a.py"),
        _note(),
    )

    rows, detail, bar = _results(report)
    assert [r.split()[0] for r in rows] == ["HIGH", "MEDIUM", "INFO"]
    assert "All 3" in bar and "Notes 1" in bar

    rows, detail, _ = _results(report, ["f"])
    assert len(rows) == 1 and rows[0].startswith("HIGH") and "HIGH — Command Injection" in detail
    rows, _, _ = _results(report, ["f", "f"])
    assert len(rows) == 1 and rows[0].startswith("MEDIUM")
    rows, _, _ = _results(report, ["f", "f", "f"])
    assert len(rows) == 1 and rows[0].startswith("INFO")
    rows, detail, _ = _results(report, ["f", "f", "f", "f"])
    assert len(rows) == 1 and rows[0].startswith("NOTE") and "NOTE — Scan Coverage" in detail
    assert "Not a vulnerability" in detail
    rows, _, bar = _results(report, ["f"] * 5)
    assert len(rows) == 3  # cycled back to All


def test_detail_panel_follows_the_highlighted_finding_and_leaves_out_missing_evidence():
    report = _report(
        _finding(file="a.py", line=3, evidence="os.system(cmd)"),
        _finding("Hardcoded Secret", "ERROR", "b.py", 9, evidence=None),
    )

    _, first, _ = _results(report)
    _, second, _ = _results(report, ["down"])

    assert "Evidence" in first and "os.system(cmd)" in first and "a.py:3" in first
    assert "HIGH — Hardcoded Secret" in second and "Evidence" not in second
    assert "Recommendation" in second and "rule-x" in second


def test_empty_views_say_so_instead_of_showing_nothing():
    rows, detail, _ = _results(_report())
    assert rows == [] and "does not prove the server is safe" in detail

    rows, detail, _ = _results(_report(_finding()), ["f", "f"])
    assert rows == [] and "No medium entries" in detail


def test_finding_text_is_shown_literally_and_never_parsed_as_markup():
    nasty = "[bold red]boom[/] [/oops] [link=http://x]click[/link]"
    report = _report(_finding(message=nasty, evidence="x = '[/bad]'", file="we[ird].py"))

    rows, detail, _ = _results(report)

    assert nasty in detail and "x = '[/bad]'" in detail
    assert "we[ird].py:3" in rows[0]


def test_hiding_a_finding_asks_first_and_hides_all_of_that_file_and_category(tmp_path):
    report = _report(_finding(file="a.py", line=1), _finding(file="a.py", line=2), _finding(file="b.py"))

    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await app.push_screen(ResultsScreen(report))
            await pilot.pause()
            await pilot.press("i")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmScreen)
            await pilot.press("n")
            await pilot.pause()
            assert len(app.screen.query_one(ListView).children) == 3
            assert not (tmp_path / ".mcpscannerignore").exists()
            await pilot.press("i")
            await pilot.pause()
            await pilot.press("y")
            await pilot.pause(0.3)
            return len(app.screen.query_one(ListView).children)

    remaining = asyncio.run(_run())

    assert remaining == 1
    assert (tmp_path / ".mcpscannerignore").read_text(encoding="utf-8").splitlines() == ["a.py:Command Injection"]


# ---------------------------------------------------------------- export


def _export(report, steps, sarif=True):
    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await app.push_screen(ExportScreen(report, sarif=sarif))
            await pilot.pause()
            return await steps(app, pilot)

    return asyncio.run(_run())


def test_export_writes_the_same_json_the_cli_prints(tmp_path):
    report = _report(_finding())

    async def steps(app, pilot):
        await pilot.press("enter")
        await pilot.pause()
        return type(app.screen)

    screen = _export(report, steps)

    assert screen is not ExportScreen  # closed after saving
    assert (tmp_path / "mcpthreat-report.json").read_text(encoding="utf-8") == render_json(report)


def test_export_as_sarif_follows_the_format_and_keeps_the_scanner_metadata(tmp_path):
    report = _report(_finding(evidence="os.system(cmd)"))

    async def steps(app, pilot):
        app.screen.query_one("#export-format", OptionList).highlighted = 1
        await pilot.pause()
        name = app.screen.query_one("#export-path", Input).value
        await pilot.press("enter")
        await pilot.pause()
        return name

    name = _export(report, steps)

    assert name == "mcpthreat-report.sarif"
    sarif = json.loads((tmp_path / name).read_text(encoding="utf-8"))
    result = sarif["runs"][0]["results"][0]
    assert sarif["version"] == "2.1.0" and result["properties"] == {"scannerRuleId": "rule-x"}
    assert result["locations"][0]["physicalLocation"]["region"]["snippet"]["text"] == "os.system(cmd)"


def test_export_asks_before_overwriting_and_rejects_folders(tmp_path):
    (tmp_path / "mcpthreat-report.json").write_text("old", encoding="utf-8")
    (tmp_path / "somefolder").mkdir()

    async def steps(app, pilot):
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmScreen)
        await pilot.press("n")
        await pilot.pause()
        assert (tmp_path / "mcpthreat-report.json").read_text(encoding="utf-8") == "old"
        app.screen.query_one("#export-path", Input).value = "somefolder"
        await pilot.press("enter")
        await pilot.pause()
        folder_error = _text(app.screen.query_one("#export-status", Static))
        app.screen.query_one("#export-path", Input).value = "mcpthreat-report.json"
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("y")
        await pilot.pause()
        return folder_error

    folder_error = _export(_report(), steps)

    assert "folder" in folder_error
    assert (tmp_path / "mcpthreat-report.json").read_text(encoding="utf-8") == render_json(_report())


def test_comparison_export_offers_json_only():
    async def steps(app, pilot):
        return len(app.screen.query_one("#export-format", OptionList).options)

    assert _export({"mode": "files"}, steps, sarif=False) == 1


# ---------------------------------------------------------------- version comparison screen


def _comparison(**changes):
    result = {
        "mode": "folders", "before": "v1", "after": "v2",
        "files": {"added": ["new.py"], "removed": ["old.py"], "modified": ["server.py"]},
        "tool_changes": [], "new_findings": [], "resolved_findings": [], "unchanged_count": 2,
    }
    return {**result, **changes}


def _comparison_screen(result, keys=()):
    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await app.push_screen(ComparisonScreen(result, duration_s=1.5))
            await pilot.pause()
            text = _text(app.screen.query_one("#comparison", Static))
            for key in keys:
                await pilot.press(key)
                await pilot.pause()
            lists = app.screen.query(ListView)
            return text, type(app.screen), len(lists.first().children) if lists else None

    return asyncio.run(_run())


def test_comparison_lists_files_tool_changes_and_new_and_resolved_findings():
    hidden = _finding("Tool Poisoning", "ERROR", "v2/server.py", None, rule_id="rugpull-behavior-changed-hidden",
                      message="Tool Poisoning (suspected rug pull): Tool 'send_mail' has identical parameters")
    result = _comparison(
        tool_changes=[hidden],
        new_findings=[_finding(file="v2/server.py", line=5)],
        resolved_findings=[_finding("Header Leak", "ERROR", "v1/old.py", 8)],
    )

    text, _, _ = _comparison_screen(result)

    assert "REVIEW SUMMARY" in text and "Tool 'send_mail' changed its code while its parameters" in text
    assert "1 new finding(s) in the current version, 1 of them HIGH" in text
    assert "1 finding(s) from the baseline no longer appear" in text
    assert "new.py" in text and "old.py" in text and "server.py" in text
    assert "TOOL DEFINITION CHANGES  1" in text and "NEW FINDINGS  1" in text and "RESOLVED FINDINGS  1" in text
    assert "2 finding(s) are present in both versions" in text
    assert "not proof of safety" in text


def test_comparison_without_changes_says_so_without_claiming_safety():
    text, _, _ = _comparison_screen(_comparison(files={"added": [], "removed": [], "modified": []}))

    assert "No changes to tool definitions or findings" in text
    assert "No file changed" in text and "not proof of safety" in text


def test_comparison_keys_open_the_new_findings_and_the_json_export():
    result = _comparison(new_findings=[_finding(file="v2/server.py", line=5)])

    _, screen_type, rows = _comparison_screen(result, ["n"])
    assert screen_type is ResultsScreen and rows == 1

    _, screen_type, _ = _comparison_screen(result, ["e"])
    assert screen_type is ExportScreen

    _, screen_type, _ = _comparison_screen(_comparison(), ["n"])
    assert screen_type is ComparisonScreen  # nothing new: the key does nothing


def test_diff_path_screen_requires_the_current_version_to_match_the_baseline_type(tmp_path):
    folder = tmp_path / "v2"
    folder.mkdir()
    file = tmp_path / "server.py"
    file.write_text("x = 1\n", encoding="utf-8")
    chosen = []

    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await app.push_screen(DiffPathScreen("Step 2", chosen.append, expect_dir=False))
            await pilot.pause()
            app.screen.query_one("#path-input", Input).value = str(folder)
            await pilot.press("enter")
            await pilot.pause()
            error = _text(app.screen.query_one("#path-status", Static))
            app.screen.query_one("#path-input", Input).value = str(file)
            await pilot.press("enter")
            await pilot.pause()
            return error

    error = asyncio.run(_run())

    assert "pick a file" in error
    assert chosen == [file]


# ---------------------------------------------------------------- trusted servers and exclusions


def _trust(steps):
    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await app.push_screen(TrustScreen())
            await pilot.pause()
            return await steps(app, pilot)

    return asyncio.run(_run())


def test_trust_screen_separates_trust_from_security_and_names_scope_and_source(tmp_path):
    async def steps(app, pilot):
        return (
            _text(app.screen.query_one("#trust-note", Static)),
            _text(app.screen.query_one("#trusted-source", Static)),
            _text(app.screen.query_one("#exclusions-source", Static)),
        )

    note, trusted_source, exclusions_source = _trust(steps)

    assert "does not make a server secure" in note and "no scan reads it" in note
    assert "Scope:" in trusted_source and str(tmp_path / "reputation.json") in trusted_source
    assert "Scope:" in exclusions_source and str(tmp_path / ".mcpscannerignore") in exclusions_source
    assert "not created yet" in exclusions_source


def test_adding_an_exclusion_writes_the_rule_once(tmp_path):
    async def steps(app, pilot):
        for _ in range(2):  # the second time is a duplicate
            await pilot.press("a")
            await pilot.pause()
            assert isinstance(app.screen, IgnoreRuleScreen)
            app.screen.query_one("#rule-file", Input).value = "tools/mail.py"
            await pilot.press("enter")
            await pilot.pause()
        return app.screen.query_one("#exclusions-table", DataTable).row_count

    rows = _trust(steps)

    assert rows == 1
    assert (tmp_path / ".mcpscannerignore").read_text(encoding="utf-8").splitlines() == ["tools/mail.py:Header Leak"]


def test_adding_an_exclusion_needs_a_file_path_and_can_be_cancelled(tmp_path):
    async def steps(app, pilot):
        await pilot.press("a")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        error = _text(app.screen.query_one("#rule-status", Static))
        await pilot.press("escape")
        await pilot.pause()
        return error, type(app.screen)

    error, screen = _trust(steps)

    assert "Enter a file path" in error and screen is TrustScreen
    assert not (tmp_path / ".mcpscannerignore").exists()


def test_editing_an_exclusion_replaces_the_old_rule(tmp_path):
    (tmp_path / ".mcpscannerignore").write_text("old.py:Header Leak\n", encoding="utf-8")

    async def steps(app, pilot):
        app.screen.query_one("#exclusions-table", DataTable).focus()
        await pilot.press("e")
        await pilot.pause()
        field = app.screen.query_one("#rule-file", Input)
        assert field.value == "old.py"
        field.value = "new.py"
        await pilot.press("enter")
        await pilot.pause()

    _trust(steps)

    assert (tmp_path / ".mcpscannerignore").read_text(encoding="utf-8").splitlines() == ["new.py:Header Leak"]


def test_cancelling_a_removal_changes_nothing(tmp_path):
    (tmp_path / ".mcpscannerignore").write_text("a.py:Header Leak\n", encoding="utf-8")
    (tmp_path / "reputation.json").write_text(json.dumps({"srv": {"version_hash": "abc", "reviewed_at": "2026-01-01"}}), encoding="utf-8")

    async def steps(app, pilot):
        await pilot.press("d")  # trusted list has the focus
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
        app.screen.query_one("#exclusions-table", DataTable).focus()
        await pilot.press("d")
        await pilot.pause()
        await pilot.press("n")
        await pilot.pause()

    _trust(steps)

    assert (tmp_path / ".mcpscannerignore").read_text(encoding="utf-8") == "a.py:Header Leak\n"
    assert "srv" in json.loads((tmp_path / "reputation.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------- settings and help


def _settings(setup=None):
    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await app.push_screen(SettingsScreen())
            await pilot.pause()
            text = _text(app.screen.query_one("#settings", Static))
            await pilot.press("k")
            await pilot.pause()
            return text, type(app.screen)

    return asyncio.run(_run())


def test_settings_show_sources_shortcuts_and_all_implemented_checks(tmp_path):
    text, screen = _settings()

    assert str(tmp_path / ".mcpscannerignore") in text and str(tmp_path / "reputation.json") in text
    assert "API key configured" in text
    for category in ("Tool Poisoning", "Command Injection", "Hardcoded Secret", "Supply Chain",
                     "Typosquatting / Shadow-Server", "Rug Pull / Version Diff"):
        assert category in text
    assert "F filter by severity" in text and "cannot be cancelled" in text
    assert "No finding does not prove" in text
    assert screen is SetupScreen  # K opens the key dialog


def test_settings_never_show_the_api_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-super-secret-value")

    text, _ = _settings()

    assert "sk-super-secret-value" not in text
    monkeypatch.delenv("OPENAI_API_KEY")
    assert "no API key set" in _settings()[0]
