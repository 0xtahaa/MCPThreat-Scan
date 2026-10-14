"""CLI error handling through both start paths (AR-132): stderr text, stdout, exit codes.

Analyzer failures are injected at the orchestrator seams (no network, no real tool failure needed).
Behaviour that is deliberately NOT translated today (E1/E2 of AR-085) is pinned as-is."""

import pytest

import mcpthreat_scan.cli.main as target
from mcpthreat_scan.analyzers.dependencies import DependencyCheckError
from mcpthreat_scan.analyzers.semgrep import SemgrepRunnerError

ORCH = "mcpthreat_scan.core.orchestrator."


@pytest.fixture
def cli_main():
    return target.main


def _run(cli_main, capsys, *argv):
    exit_code = cli_main(list(argv))
    captured = capsys.readouterr()
    return exit_code, captured.out, captured.err


def test_missing_scan_path_exits_one_with_message_and_no_stdout(cli_main, capsys):
    exit_code, out, err = _run(cli_main, capsys, "scan", "does/not/exist.py")

    assert (exit_code, out) == (1, "")
    assert err.startswith("Path not found: ")


def test_semgrep_failure_is_translated_to_a_prefixed_message(cli_main, capsys, monkeypatch, tmp_path):
    def broken(target_path):
        raise SemgrepRunnerError("semgrep failed (exit 7): broken")

    monkeypatch.setattr(ORCH + "run_semgrep_rules", broken)

    exit_code, out, err = _run(cli_main, capsys, "scan", str(tmp_path))

    assert (exit_code, out) == (1, "")
    assert err == "Semgrep error: semgrep failed (exit 7): broken\n"


def test_dependency_failure_is_translated_to_a_prefixed_message(cli_main, capsys, monkeypatch, tmp_path):
    def broken(path):
        raise DependencyCheckError("pip-audit failed (exit 3): broken")

    (tmp_path / "requirements.txt").write_text("urllib3==1.26.4\n", encoding="utf-8")
    monkeypatch.setattr(ORCH + "run_semgrep_rules", lambda target_path: [])
    monkeypatch.setattr(ORCH + "check_requirements_file", broken)

    exit_code, out, err = _run(cli_main, capsys, "scan", str(tmp_path))

    assert (exit_code, out) == (1, "")
    assert err == "Supply chain check error: pip-audit failed (exit 3): broken\n"


def test_diff_syntax_error_is_translated_and_diff_paths_are_checked_first(cli_main, capsys, tmp_path):
    broken = tmp_path / "broken.py"
    broken.write_text("def broken(:\n", encoding="utf-8")

    assert _run(cli_main, capsys, "diff", str(broken), str(broken))[2].startswith("Rug-pull diff error:")
    exit_code, _, err = _run(cli_main, capsys, "diff", "does/not/exist.py", str(broken))
    assert exit_code == 1 and err.startswith("Path not found: ")


@pytest.mark.parametrize("argv", [["scan"], ["scan", "p", "--format", "xml"], ["nope"], []])
def test_usage_errors_exit_two_via_argparse(cli_main, capsys, argv):
    with pytest.raises(SystemExit) as excinfo:
        cli_main(argv)

    assert excinfo.value.code == 2
    assert capsys.readouterr().err.startswith("usage: cli.main")


def test_failing_threshold_is_exit_one_but_after_a_complete_report(cli_main, capsys, monkeypatch, tmp_path):
    report = {
        "target": "t",
        "findings": [{"category": "Header Leak", "file": "a.py", "line": 1, "severity": "ERROR", "message": "m"}],
        "summary": {"categories_checked": 9, "categories_without_finding": 8, "categories_with_finding": ["Header Leak"]},
    }
    monkeypatch.setattr(target, "run_scan", lambda *a, **k: report)

    exit_code, out, err = _run(cli_main, capsys, "scan", str(tmp_path), "--fail-on", "ERROR")

    assert (exit_code, err) == (1, "")
    assert out.rstrip().endswith("Categories with findings: Header Leak")


def test_untranslated_errors_still_propagate_as_exceptions(cli_main, monkeypatch, tmp_path):
    # E2 (AR-085): a non-UTF-8 .py file crashes the typosquat stage; not translated, pinned as-is.
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe\x00 not utf-8")
    monkeypatch.setattr(ORCH + "run_semgrep_rules", lambda target_path: [])

    with pytest.raises(UnicodeDecodeError):
        cli_main(["scan", str(tmp_path)])
