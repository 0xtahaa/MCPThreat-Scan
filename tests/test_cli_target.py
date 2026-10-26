"""Target CLI (mcpthreat_scan.cli.main) wires arguments to the core API (AR-126).

Analysis is replaced by fakes here, so these tests check only the wiring: which core entry point
is called with which arguments, what is printed, and which exit code results."""

import json

import pytest

import mcpthreat_scan.cli.main as target
from mcpthreat_scan.core.exceptions import ReportError

SUMMARY = {"categories_checked": 9, "categories_without_finding": 8, "categories_with_finding": ["Header Leak"]}
REPORT = {
    "target": "t",
    "findings": [{"category": "Header Leak", "file": "a.py", "line": 3, "severity": "WARNING", "message": "m"}],
    "summary": SUMMARY,
}


@pytest.fixture
def calls(monkeypatch):
    recorded = []
    monkeypatch.setattr(target, "run_scan", lambda *a, **k: recorded.append(("scan", a, k)) or REPORT)
    monkeypatch.setattr(target, "run_diff", lambda *a, **k: recorded.append(("diff", a, k)) or REPORT)
    return recorded


def test_scan_calls_run_scan_with_path_and_ai_flag_only(calls, tmp_path, capsys):
    exit_code = target.main(["scan", str(tmp_path), "--ai-review"])

    assert exit_code == 0
    assert calls == [("scan", (tmp_path,), {"ai_review": True})]
    assert "[Header Leak] WARNING: m" in capsys.readouterr().out


def test_scan_without_ai_flag_passes_false(calls, tmp_path):
    target.main(["scan", str(tmp_path)])

    assert calls[0][2] == {"ai_review": False}


def test_diff_calls_run_diff_with_both_paths(calls, tmp_path, capsys):
    before, after = tmp_path / "a.py", tmp_path / "b.py"
    before.write_text("x", encoding="utf-8")
    after.write_text("y", encoding="utf-8")

    exit_code = target.main(["diff", str(before), str(after), "--format", "json"])

    assert exit_code == 0
    assert calls == [("diff", (before, after), {})]
    assert json.loads(capsys.readouterr().out) == REPORT


def test_missing_paths_are_reported_before_any_core_call(calls, tmp_path, capsys):
    assert target.main(["scan", str(tmp_path / "nope")]) == 1
    assert target.main(["diff", str(tmp_path / "nope"), str(tmp_path)]) == 1
    assert calls == []
    assert capsys.readouterr().err.count("Path not found") == 2


def test_report_error_becomes_stderr_and_exit_one_without_stdout(monkeypatch, tmp_path, capsys):
    def boom(*args, **kwargs):
        raise ReportError("Semgrep error: broken")

    monkeypatch.setattr(target, "run_scan", boom)

    assert target.main(["scan", str(tmp_path)]) == 1
    captured = capsys.readouterr()
    assert captured.err == "Semgrep error: broken\n"
    assert captured.out == ""


def test_fail_on_is_evaluated_after_the_report_is_printed(calls, tmp_path, capsys):
    assert target.main(["scan", str(tmp_path), "--fail-on", "WARNING"]) == 1
    assert "Summary" in capsys.readouterr().out
    assert target.main(["scan", str(tmp_path), "--fail-on", "ERROR"]) == 0


def test_tui_without_injected_starter_starts_the_target_tui_app(monkeypatch):
    import mcpthreat_scan.tui.app as tui_app

    started = []
    monkeypatch.setattr(tui_app, "run", lambda: started.append(True))

    assert target.main(["tui"]) == 0
    assert started == [True]


def test_tui_uses_the_injected_starter():
    started = []

    assert target.main(["tui"], run_tui=lambda: started.append(True)) == 0
    assert started == [True]


def test_parser_program_name_is_mcpthreat_scan(capsys):
    with pytest.raises(SystemExit) as excinfo:
        target.main([])

    assert excinfo.value.code == 2
    assert capsys.readouterr().err.startswith("usage: mcpthreat-scan ")
