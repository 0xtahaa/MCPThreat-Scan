"""Characterization test (AR-087 X0b): error paths of scan and diff (AR-085).

Documents today's behaviour, including untranslated exceptions. A change here needs
its own approved task."""

import pytest

from mcpthreat_scan.analyzers.ai_review import AIReviewError  # noqa: F401  (contract reference)
from mcpthreat_scan.analyzers.dependencies import DependencyCheckError
from mcpthreat_scan.analyzers.semgrep import SemgrepRunnerError
from mcpthreat_scan.cli.main import main
from mcpthreat_scan.core.orchestrator import run_diff, run_scan

PATCH = {
    "semgrep": "mcpthreat_scan.core.orchestrator.run_semgrep_rules",
    "deps": "mcpthreat_scan.core.orchestrator.check_requirements_file",
    "ai": "mcpthreat_scan.core.orchestrator.review_candidate",
}
CANDIDATE = {
    "category": "Tool Poisoning", "file": "benchmark/vulnerable/tool_poisoning_docstring.py",
    "line": 4, "severity": "WARNING", "message": "m",
    "rule_id": "rules.tool-poisoning-docstring-candidate",
}


def _raise(exc):
    def raiser(*args, **kwargs):
        raise exc
    return raiser


def _dir_with(tmp_path, **files):
    for name, content in files.items():
        (tmp_path / name).write_bytes(content)
    return tmp_path


def test_semgrep_error_is_translated_and_cli_exits_1(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(PATCH["semgrep"], _raise(SemgrepRunnerError("boom")))

    code = main(["scan", str(_dir_with(tmp_path, **{"a.py": b"x = 1\n"}))])

    captured = capsys.readouterr()
    assert code == 1
    assert captured.err.startswith("Semgrep error: boom")
    assert captured.out == ""


def test_dependency_error_is_translated_and_cli_exits_1(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(PATCH["semgrep"], lambda target: [])
    monkeypatch.setattr(PATCH["deps"], _raise(DependencyCheckError("boom")))

    code = main(["scan", str(_dir_with(tmp_path, **{"requirements.txt": b"x==1\n"}))])

    captured = capsys.readouterr()
    assert code == 1
    assert captured.err.startswith("Supply chain check error: boom")
    assert captured.out == ""


def test_diff_syntax_error_is_translated_and_cli_exits_1(tmp_path, capsys):
    before = tmp_path / "a.py"
    after = tmp_path / "b.py"
    before.write_bytes(b"def f(:\n")
    after.write_bytes(b"def f(:\n")

    code = main(["diff", str(before), str(after)])

    captured = capsys.readouterr()
    assert code == 1
    assert captured.err.startswith("Rug-pull diff error: ")
    assert captured.out == ""


def test_argparse_usage_error_exits_2(capsys):
    with pytest.raises(SystemExit) as info:
        main(["scan"])

    assert info.value.code == 2


def test_typosquat_skips_files_with_syntax_errors_silently(tmp_path, monkeypatch):
    monkeypatch.setattr(PATCH["semgrep"], lambda target: [])

    report = run_scan(_dir_with(tmp_path, **{"broken.py": b"def f(:\n"}))

    assert report["findings"] == []


def test_invalid_utf8_in_scanned_folder_stays_untranslated(tmp_path, monkeypatch):
    monkeypatch.setattr(PATCH["semgrep"], lambda target: [])

    with pytest.raises(UnicodeDecodeError):
        run_scan(_dir_with(tmp_path, **{"bad.py": b"\xff\xfe\x00 bad\n"}))


def test_invalid_utf8_in_diff_stays_untranslated(tmp_path):
    bad = tmp_path / "bad.py"
    good = tmp_path / "good.py"
    bad.write_bytes(b"\xff\xfe\x00 bad\n")
    good.write_bytes(b"def f():\n    pass\n")

    with pytest.raises(UnicodeDecodeError):
        run_diff(bad, good)


def test_invalid_pyproject_toml_stays_untranslated(tmp_path, monkeypatch):
    import tomllib

    monkeypatch.setattr(PATCH["semgrep"], lambda target: [])

    with pytest.raises(tomllib.TOMLDecodeError):
        run_scan(_dir_with(tmp_path, **{"pyproject.toml": b"not = valid = toml\n"}))


def test_non_ai_review_error_in_ai_step_stays_untranslated(monkeypatch):
    monkeypatch.setattr(PATCH["semgrep"], lambda target: [dict(CANDIDATE)])
    monkeypatch.setattr(PATCH["ai"], _raise(RuntimeError("HTTP 401")))

    with pytest.raises(RuntimeError):
        run_scan("benchmark/vulnerable/tool_poisoning_docstring.py", ai_review=True)
