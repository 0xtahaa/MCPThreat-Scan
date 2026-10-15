"""Isolated tests of the pipeline stages in core.orchestrator (AR-091 onward)."""

from pathlib import Path

import pytest

from mcpthreat_scan.analyzers.ai_review import AIReviewError
from mcpthreat_scan.analyzers.semgrep import SemgrepRunnerError
from mcpthreat_scan.core import orchestrator
from mcpthreat_scan.core.exceptions import ReportError


def test_semgrep_stage_returns_runner_result_unchanged(monkeypatch):
    findings = [{"category": "Command Injection", "file": "a.py", "line": 1,
                 "severity": "ERROR", "message": "m", "rule_id": "r"}]
    seen = []
    monkeypatch.setattr(
        orchestrator, "run_semgrep_rules", lambda target: seen.append(target) or findings
    )

    assert orchestrator._run_semgrep_stage(Path("x")) is findings
    assert seen == [Path("x")]


def test_semgrep_stage_translates_runner_error_and_keeps_cause(monkeypatch):
    original = SemgrepRunnerError("boom")

    def raiser(target):
        raise original

    monkeypatch.setattr(orchestrator, "run_semgrep_rules", raiser)

    with pytest.raises(ReportError) as info:
        orchestrator._run_semgrep_stage(Path("x"))

    assert str(info.value) == "Semgrep error: boom"
    assert info.value.__cause__ is original


def test_semgrep_stage_does_not_translate_other_errors(monkeypatch):
    def raiser(target):
        raise RuntimeError("other")

    monkeypatch.setattr(orchestrator, "run_semgrep_rules", raiser)

    with pytest.raises(RuntimeError):
        orchestrator._run_semgrep_stage(Path("x"))


DEP = [{"name": "pkg", "version": "1.0", "vulnerabilities": [{"id": "CVE-X"}, {"id": "CVE-Y"}]}]


def _patch_dependency_checks(monkeypatch, calls, *, pep621=True):
    def make(name):
        def fake(path):
            calls.append((name, Path(path)))
            return DEP
        return fake

    monkeypatch.setattr(orchestrator, "check_requirements_file", make("requirements"))
    monkeypatch.setattr(orchestrator, "check_pyproject_dependencies", make("pyproject"))
    monkeypatch.setattr(orchestrator, "check_poetry_lock_dependencies", make("poetry"))
    monkeypatch.setattr(orchestrator, "has_pep621_dependencies", lambda path: pep621)


def _dir(tmp_path, *names):
    for name in names:
        (tmp_path / name).write_text("", encoding="utf-8")
    return tmp_path


def test_dependency_stage_skips_single_files(tmp_path, monkeypatch):
    calls = []
    _patch_dependency_checks(monkeypatch, calls)
    target = tmp_path / "server.py"
    target.write_text("x = 1\n", encoding="utf-8")

    assert orchestrator._run_dependency_stage(target) == []
    assert calls == []


def test_dependency_stage_empty_directory_has_no_findings(tmp_path, monkeypatch):
    calls = []
    _patch_dependency_checks(monkeypatch, calls)

    assert orchestrator._run_dependency_stage(tmp_path) == []
    assert calls == []


@pytest.mark.parametrize(
    "files, pep621, expected_call",
    [
        (["requirements.txt", "pyproject.toml", "poetry.lock"], True, "requirements"),
        (["pyproject.toml", "poetry.lock"], True, "pyproject"),
        (["pyproject.toml", "poetry.lock"], False, "poetry"),
        (["poetry.lock"], True, "poetry"),
    ],
    ids=["requirements-wins", "pep621", "pyproject-falls-to-poetry", "poetry-only"],
)
def test_dependency_stage_source_priority(tmp_path, monkeypatch, files, pep621, expected_call):
    calls = []
    _patch_dependency_checks(monkeypatch, calls, pep621=pep621)

    rows = orchestrator._run_dependency_stage(_dir(tmp_path, *files))

    assert [name for name, _ in calls] == [expected_call]
    assert len(rows) == 1
    assert rows[0]["category"] == "Supply Chain"
    assert rows[0]["message"] == "pkg==1.0: CVE-X, CVE-Y"
    assert rows[0]["line"] is None and rows[0]["severity"] == "ERROR"


def test_dependency_stage_pyproject_without_pep621_or_lock_checks_nothing(tmp_path, monkeypatch):
    calls = []
    _patch_dependency_checks(monkeypatch, calls, pep621=False)

    assert orchestrator._run_dependency_stage(_dir(tmp_path, "pyproject.toml")) == []
    assert calls == []


def test_dependency_stage_translates_check_error_and_keeps_cause(tmp_path, monkeypatch):
    original = orchestrator.DependencyCheckError("boom")

    def raiser(path):
        raise original

    monkeypatch.setattr(orchestrator, "check_requirements_file", raiser)

    with pytest.raises(ReportError) as info:
        orchestrator._run_dependency_stage(_dir(tmp_path, "requirements.txt"))

    assert str(info.value) == "Supply chain check error: boom"
    assert info.value.__cause__ is original


def test_dependency_stage_does_not_translate_other_errors(tmp_path, monkeypatch):
    def raiser(path):
        raise RuntimeError("other")

    monkeypatch.setattr(orchestrator, "check_requirements_file", raiser)

    with pytest.raises(RuntimeError):
        orchestrator._run_dependency_stage(_dir(tmp_path, "requirements.txt"))


def test_typosquat_stage_single_file_only_checks_that_file(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(
        orchestrator, "check_typosquat", lambda path: seen.append(Path(path)) or [{"m": 1}]
    )
    target = tmp_path / "server.py"
    target.write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "other.py").write_text("y = 2\n", encoding="utf-8")

    assert orchestrator._run_typosquat_stage(target) == [{"m": 1}]
    assert seen == [target]


def test_typosquat_stage_folder_checks_py_files_sorted_and_recursive(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(
        orchestrator, "check_typosquat", lambda path: seen.append(Path(path).name) or []
    )
    (tmp_path / "sub").mkdir()
    for name in ("b.py", "a.py", "sub/c.py", "notes.txt"):
        (tmp_path / name).write_text("", encoding="utf-8")

    assert orchestrator._run_typosquat_stage(tmp_path) == []
    assert seen == sorted(seen, key=lambda n: n) and set(seen) == {"a.py", "b.py", "c.py"}
    assert seen == [p.name for p in sorted(tmp_path.rglob("*.py"))]


def test_typosquat_stage_skips_unreadable_and_syntax_error_files(tmp_path, monkeypatch):
    def check(path):
        if Path(path).name == "bad.py":
            raise SyntaxError("x")
        if Path(path).name == "gone.py":
            raise OSError("x")
        return [{"ok": Path(path).name}]

    monkeypatch.setattr(orchestrator, "check_typosquat", check)
    for name in ("bad.py", "gone.py", "good.py"):
        (tmp_path / name).write_text("", encoding="utf-8")

    assert orchestrator._run_typosquat_stage(tmp_path) == [{"ok": "good.py"}]


def test_typosquat_stage_does_not_swallow_other_errors(tmp_path, monkeypatch):
    def check(path):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")

    monkeypatch.setattr(orchestrator, "check_typosquat", check)
    (tmp_path / "a.py").write_text("", encoding="utf-8")

    with pytest.raises(UnicodeDecodeError):
        orchestrator._run_typosquat_stage(tmp_path)


def _candidate(rule="rules.tool-poisoning-docstring-candidate"):
    return {"category": "Tool Poisoning", "file": "t.py", "line": 3, "severity": "WARNING",
            "message": "orig", "rule_id": rule}


def test_ai_stage_passes_other_findings_through_without_calling_the_model(monkeypatch):
    def fail(text):
        raise AssertionError("review_candidate must not run")

    monkeypatch.setattr(orchestrator, "review_candidate", fail)
    other = _candidate(rule="rules.command-injection")

    result = orchestrator._apply_ai_review([other])

    assert result == [other] and result[0] is other


def test_ai_stage_keeps_candidate_when_docstring_cannot_be_extracted(monkeypatch):
    monkeypatch.setattr(orchestrator, "extract_docstring_at_line", lambda path, line: None)
    monkeypatch.setattr(
        orchestrator, "review_candidate", lambda text: pytest.fail("must not be called")
    )
    finding = _candidate()

    result = orchestrator._apply_ai_review([finding])

    assert result == [finding] and result[0] is not finding  # shallow copy


def test_ai_stage_confirmed_verdict_promotes_to_error_without_mutating_input(monkeypatch):
    seen = []
    monkeypatch.setattr(orchestrator, "extract_docstring_at_line", lambda path, line: "DOC")
    monkeypatch.setattr(
        orchestrator, "review_candidate",
        lambda text: seen.append(text) or {"suspicious": True, "reasoning": "why", "confidence": 0.9},
    )
    finding = _candidate()

    (result,) = orchestrator._apply_ai_review([finding])

    assert seen == ["DOC"]
    assert result["severity"] == "ERROR"
    assert result["message"] == (
        "Tool Poisoning (layer-2 AI review CONFIRMED): why (confidence: 0.90)"
    )
    assert finding["severity"] == "WARNING" and finding["message"] == "orig"


def test_ai_stage_cleared_verdict_downgrades_to_info(monkeypatch):
    monkeypatch.setattr(orchestrator, "extract_docstring_at_line", lambda path, line: "DOC")
    monkeypatch.setattr(
        orchestrator, "review_candidate",
        lambda text: {"suspicious": False, "reasoning": "fine", "confidence": 0.25},
    )

    (result,) = orchestrator._apply_ai_review([_candidate()])

    assert result["severity"] == "INFO"
    assert result["message"] == (
        "Tool Poisoning (layer-2 AI review: no tool poisoning detected, "
        "candidate dismissed): fine (confidence: 0.25)"
    )


def test_ai_stage_review_error_keeps_candidate_and_appends_note(monkeypatch):
    def raiser(text):
        raise AIReviewError("no key")

    monkeypatch.setattr(orchestrator, "extract_docstring_at_line", lambda path, line: "DOC")
    monkeypatch.setattr(orchestrator, "review_candidate", raiser)

    (result,) = orchestrator._apply_ai_review([_candidate()])

    assert result["severity"] == "WARNING"
    assert result["message"] == "orig [Automatic layer-2 review not possible: no key]"


def test_ai_stage_other_errors_stay_untranslated(monkeypatch):
    def raiser(text):
        raise RuntimeError("HTTP 401")

    monkeypatch.setattr(orchestrator, "extract_docstring_at_line", lambda path, line: "DOC")
    monkeypatch.setattr(orchestrator, "review_candidate", raiser)

    with pytest.raises(RuntimeError):
        orchestrator._apply_ai_review([_candidate()])


def test_ai_stage_output_candidate_uses_return_text_not_docstring(monkeypatch):
    seen = []
    monkeypatch.setattr(
        orchestrator, "extract_docstring_at_line", lambda path, line: pytest.fail("wrong extractor")
    )
    monkeypatch.setattr(orchestrator, "extract_return_text_at_line", lambda path, line: "OUT")
    monkeypatch.setattr(
        orchestrator, "review_candidate",
        lambda text: seen.append(text) or {"suspicious": True, "reasoning": "why", "confidence": 0.8},
    )

    (result,) = orchestrator._apply_ai_review([_candidate(rule="rules.tool-poisoning-output-candidate")])

    assert seen == ["OUT"]
    assert result["severity"] == "ERROR"


def test_ai_stage_output_candidate_kept_when_return_text_cannot_be_extracted(monkeypatch):
    monkeypatch.setattr(orchestrator, "extract_return_text_at_line", lambda path, line: None)
    monkeypatch.setattr(
        orchestrator, "review_candidate", lambda text: pytest.fail("must not be called")
    )
    finding = _candidate(rule="rules.tool-poisoning-output-candidate")

    (result,) = orchestrator._apply_ai_review([finding])

    assert result == finding and result["severity"] == "WARNING"


def test_ignore_stage_loads_rules_then_applies_them(monkeypatch):
    calls = []
    rules = {("a.py", "Tool Poisoning")}
    findings = [{"file": "a.py", "category": "Tool Poisoning"}]
    monkeypatch.setattr(
        orchestrator, "load_ignore_rules", lambda path: calls.append(("load", path)) or rules
    )
    monkeypatch.setattr(
        orchestrator, "apply_ignore_rules",
        lambda items, given: calls.append(("apply", items, given)) or ([], 1),
    )

    assert orchestrator._apply_ignore_stage(findings, "ign") == ([], 1)
    assert calls == [("load", "ign"), ("apply", findings, rules)]


def test_ignore_stage_without_file_keeps_everything(tmp_path):
    findings = [{"file": "a.py", "category": "Tool Poisoning"}]

    kept, suppressed = orchestrator._apply_ignore_stage(findings, tmp_path / "missing")

    assert kept == findings and suppressed == 0


def test_ignore_stage_suppresses_matching_pair(tmp_path):
    ignore_file = tmp_path / "ign"
    ignore_file.write_text("a.py:Tool Poisoning\n", encoding="utf-8")
    findings = [
        {"file": "a.py", "category": "Tool Poisoning"},
        {"file": "a.py", "category": "Command Injection"},
    ]

    kept, suppressed = orchestrator._apply_ignore_stage(findings, ignore_file)

    assert kept == [{"file": "a.py", "category": "Command Injection"}] and suppressed == 1


RUGPULL_CASES = [
    ({"change": "tool_added", "tool": "t"}, "INFO",
     "Tool Poisoning: New tool 't' was added in the new version."),
    ({"change": "tool_removed", "tool": "t"}, "INFO",
     "Tool Poisoning: Tool 't' is no longer present in the new version."),
    ({"change": "parameters_changed", "tool": "t",
      "details": [{"parameter": "a", "change": "added"}, {"parameter": "b", "change": "removed"}]},
     "WARNING",
     "Tool Poisoning: Parameters of tool 't' changed: a (added), b (removed)."),
    ({"change": "docstring_changed", "tool": "t"}, "WARNING",
     "Tool Poisoning: Docstring/tool description of tool 't' changed."),
    ({"change": "behavior_changed_hidden", "tool": "t"}, "ERROR",
     "Tool Poisoning (suspected rug pull): Tool 't' has identical parameters and "
     "an identical docstring in both versions, but the function body has "
     "changed. A human comparing only signature/documentation would NOT "
     "notice this change."),
]


@pytest.mark.parametrize("raw, severity, message", RUGPULL_CASES, ids=lambda v: v if isinstance(v, str) and v.isupper() else None)
def test_diff_stage_converts_every_change_type(monkeypatch, raw, severity, message):
    monkeypatch.setattr(orchestrator, "diff_tool_schema_files", lambda before, after: [raw])

    rows = orchestrator._run_diff_stage(Path("old.py"), Path("new.py"))

    rule_id = "rugpull-" + raw["change"].replace("_", "-")
    assert rows == [{"category": "Tool Poisoning", "file": "new.py", "line": None,
                     "severity": severity, "message": message, "rule_id": rule_id}]
    assert list(rows[0]) == ["category", "file", "line", "severity", "message", "rule_id"]


def test_diff_stage_without_changes_returns_no_rows(monkeypatch):
    monkeypatch.setattr(orchestrator, "diff_tool_schema_files", lambda before, after: [])

    assert orchestrator._run_diff_stage(Path("a"), Path("b")) == []


@pytest.mark.parametrize("error", [OSError("gone"), SyntaxError("bad")], ids=["oserror", "syntax"])
def test_diff_stage_translates_read_and_syntax_errors(monkeypatch, error):
    def raiser(before, after):
        raise error

    monkeypatch.setattr(orchestrator, "diff_tool_schema_files", raiser)

    with pytest.raises(ReportError) as info:
        orchestrator._run_diff_stage(Path("a"), Path("b"))

    assert str(info.value).startswith("Rug-pull diff error: ")
    assert info.value.__cause__ is error


def test_diff_stage_leaves_decode_errors_untranslated(monkeypatch):
    def raiser(before, after):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")

    monkeypatch.setattr(orchestrator, "diff_tool_schema_files", raiser)

    with pytest.raises(UnicodeDecodeError):
        orchestrator._run_diff_stage(Path("a"), Path("b"))
