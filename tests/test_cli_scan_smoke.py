"""Scan command through both start paths: AR-010 smoke invariants, AI opt-in, ignore, --fail-on (AR-129).

Real Semgrep runs on the benchmark fixtures; the AI call and the ignore file are replaced at the
orchestrator seams (no network, no file in the repository root is written)."""

import json
from pathlib import Path

import pytest

import mcpthreat_scan.cli.main as target
from mcpthreat_scan.analyzers.ai_review import AIReviewError

V = "benchmark/vulnerable/"
INJECTION = V + "command_injection.py"
POISONING = V + "tool_poisoning_docstring.py"


@pytest.fixture
def cli_main():
    return target.main


def _run(cli_main, capsys, *argv):
    exit_code = cli_main(list(argv))
    captured = capsys.readouterr()
    return exit_code, captured.out, captured.err


def test_clean_file_text_says_no_findings(cli_main, capsys):
    exit_code, out, _ = _run(cli_main, capsys, "scan", "benchmark/clean/example_server_weather.py")

    assert exit_code == 0
    assert "No findings." in out and "9 of 9" in out


def test_default_text_output_lists_the_error_finding_but_exits_zero(cli_main, capsys):
    exit_code, out, _ = _run(cli_main, capsys, "scan", INJECTION)

    assert exit_code == 0
    assert "Command Injection" in out and "ERROR" in out and "Line 9" in out


def test_json_output_is_valid_with_expected_first_finding(cli_main, capsys):
    exit_code, out, _ = _run(cli_main, capsys, "scan", INJECTION, "--format", "json")

    report = json.loads(out)
    assert exit_code == 0
    assert report["findings"][0]["category"] == "Command Injection"
    assert report["summary"]["categories_without_finding"] == 8


def test_sarif_output_is_valid_with_expected_result(cli_main, capsys):
    exit_code, out, _ = _run(cli_main, capsys, "scan", INJECTION, "--format", "sarif")

    sarif = json.loads(out)
    result = sarif["runs"][0]["results"][0]
    assert (exit_code, sarif["version"]) == (0, "2.1.0")
    assert (result["ruleId"], result["level"]) == ("command-injection", "error")


@pytest.mark.parametrize(
    ("fixture", "threshold", "expected_exit"),
    [
        (INJECTION, "ERROR", 1),
        (V + "unscoped_environ.py", "ERROR", 0),
        (V + "unscoped_environ.py", "WARNING", 1),
        (V + "unscoped_environ.py", "INFO", 1),
    ],
)
def test_fail_on_threshold_decides_the_exit_code(cli_main, capsys, fixture, threshold, expected_exit):
    exit_code, out, _ = _run(cli_main, capsys, "scan", fixture, "--fail-on", threshold)

    assert exit_code == expected_exit
    assert "Summary" in out  # the report is printed before the exit code is decided


def test_ai_review_is_off_by_default(cli_main, capsys, monkeypatch):
    def fail_if_called(text):
        raise AssertionError("AI review must be opt-in")

    monkeypatch.setattr("mcpthreat_scan.core.orchestrator.review_candidate", fail_if_called)

    exit_code, out, _ = _run(cli_main, capsys, "scan", POISONING)

    assert exit_code == 0
    assert "CONFIRMED" not in out


def test_ai_review_flag_promotes_a_confirmed_candidate(cli_main, capsys, monkeypatch):
    monkeypatch.setattr(
        "mcpthreat_scan.core.orchestrator.review_candidate",
        lambda text: {"suspicious": True, "reasoning": "hidden instruction", "confidence": 0.9},
    )

    exit_code, out, _ = _run(cli_main, capsys, "scan", POISONING, "--ai-review")

    assert exit_code == 0
    assert "CONFIRMED" in out and "ERROR" in out


def test_ai_review_with_missing_key_keeps_the_candidate_and_notes_it(cli_main, capsys, monkeypatch):
    def missing_key(text):
        raise AIReviewError("OPENAI_API_KEY is not set.")

    monkeypatch.setattr("mcpthreat_scan.core.orchestrator.review_candidate", missing_key)

    exit_code, out, _ = _run(cli_main, capsys, "scan", POISONING, "--ai-review")

    assert exit_code == 0
    assert "Automatic layer-2 review not possible" in out
    assert "WARNING" in out


def test_ignore_rules_suppress_a_finding_and_are_reported(cli_main, capsys, monkeypatch):
    rule = (str(Path(INJECTION)), "Command Injection")
    monkeypatch.setattr("mcpthreat_scan.core.orchestrator.load_ignore_rules", lambda ignore_file: {rule})

    exit_code, out, _ = _run(cli_main, capsys, "scan", INJECTION)

    assert exit_code == 0
    assert "No findings." in out
    assert "1 finding(s) suppressed by .mcpscannerignore." in out
