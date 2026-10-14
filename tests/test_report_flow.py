"""Characterization test (AR-087 X0a): order of the run_scan steps.

Every step is replaced by a recorder through ONE table. When a step moves to
another module, only its line in TARGETS changes."""

import importlib

import pytest

from mcpthreat_scan.analyzers.dependencies import DependencyCheckError
from mcpthreat_scan.analyzers.semgrep import SemgrepRunnerError
from mcpthreat_scan.core.exceptions import ReportError
from mcpthreat_scan.core.orchestrator import run_scan

TARGETS = {
    "semgrep": "mcpthreat_scan.core.orchestrator.run_semgrep_rules",
    "capability": "mcpthreat_scan.core.orchestrator._filter_capability_mismatch_candidates",
    "ai": "mcpthreat_scan.core.orchestrator._apply_ai_review",
    "typosquat": "mcpthreat_scan.core.orchestrator._run_typosquat_stage",
    "has_pep621": "mcpthreat_scan.core.orchestrator.has_pep621_dependencies",
    "deps_requirements": "mcpthreat_scan.core.orchestrator.check_requirements_file",
    "deps_pyproject": "mcpthreat_scan.core.orchestrator.check_pyproject_dependencies",
    "deps_poetry": "mcpthreat_scan.core.orchestrator.check_poetry_lock_dependencies",
    "ignore_load": "mcpthreat_scan.core.orchestrator.load_ignore_rules",
    "ignore_apply": "mcpthreat_scan.core.orchestrator.apply_ignore_rules",
    "summary": "mcpthreat_scan.core.orchestrator._build_summary",
}

RAW = [
    {"category": "Command Injection", "file": "t/a.py", "line": 1, "severity": "ERROR",
     "message": "A", "rule_id": "rules.command-injection"},
    {"category": "Capability Mismatch", "file": "t/b.py", "line": 2, "severity": "WARNING",
     "message": "B", "rule_id": "rules.capability-mismatch-email-candidate"},
    {"category": "Tool Poisoning", "file": "t/c.py", "line": 3, "severity": "WARNING",
     "message": "C", "rule_id": "rules.tool-poisoning-docstring-candidate"},
]
TYPO = [{"category": "Typosquatting / Shadow-Server", "file": "t/d.py", "line": 4,
         "severity": "WARNING", "message": "D"}]
DEP = [{"name": "pkg", "version": "1.0", "vulnerabilities": [{"id": "CVE-X"}]}]

HEAD = ["semgrep", "capability"]
TAIL = ["typosquat"]
POLICY = ["ignore_load", "ignore_apply", "summary"]


def _resolve(path):
    module, attr = path.rsplit(".", 1)
    return getattr(importlib.import_module(module), attr)


def _install(monkeypatch, events, *, pep621=True, semgrep_error=False,
             dependency_error=False, suppress=0):
    seen = {}
    real_summary = _resolve(TARGETS["summary"])

    def dependency(*args, **kwargs):
        if dependency_error:
            raise DependencyCheckError("boom")
        return DEP

    def semgrep(target):
        if semgrep_error:
            raise SemgrepRunnerError("boom")
        return [dict(item) for item in RAW]

    def capability(findings):
        seen["capability_in"] = len(findings)
        return [f for f in findings if "capability-mismatch" not in f["rule_id"]]

    def ai(findings):
        seen["ai_in"] = [f["message"] for f in findings]
        return findings

    def ignore_apply(findings, rules):
        seen["ignore_in"] = len(findings)
        return (findings[suppress:], suppress) if suppress else (findings, 0)

    def summary(findings):
        seen["summary_in"] = len(findings)
        return real_summary(findings)

    steps = {
        "semgrep": semgrep, "capability": capability, "ai": ai,
        "typosquat": lambda target: TYPO,
        "has_pep621": lambda path: pep621,
        "deps_requirements": dependency, "deps_pyproject": dependency,
        "deps_poetry": dependency,
        "ignore_load": lambda path: set(),
        "ignore_apply": ignore_apply, "summary": summary,
    }
    for name, function in steps.items():
        def recorder(*args, _name=name, _function=function, **kwargs):
            events.append(_name)
            return _function(*args, **kwargs)
        monkeypatch.setattr(TARGETS[name], recorder)
    return seen


def _target(tmp_path, files):
    if files is None:
        path = tmp_path / "server.py"
        path.write_text("x = 1\n", encoding="utf-8")
        return path
    for name in files:
        (tmp_path / name).write_text("", encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize(
    "files, ai_review, pep621, expected",
    [
        (None, False, True, HEAD + TAIL + POLICY),
        (None, True, True, HEAD + ["ai"] + TAIL + POLICY),
        ([], False, True, HEAD + TAIL + POLICY),
        (["requirements.txt", "pyproject.toml", "poetry.lock"], False, True,
         HEAD + TAIL + ["deps_requirements"] + POLICY),
        (["pyproject.toml", "poetry.lock"], False, True,
         HEAD + TAIL + ["has_pep621", "deps_pyproject"] + POLICY),
        (["pyproject.toml", "poetry.lock"], False, False,
         HEAD + TAIL + ["has_pep621", "deps_poetry"] + POLICY),
        (["poetry.lock"], False, True, HEAD + TAIL + ["deps_poetry"] + POLICY),
        (["pyproject.toml"], False, False, HEAD + TAIL + ["has_pep621"] + POLICY),
    ],
    ids=["file", "file+ai", "empty-dir", "requirements-wins", "pep621",
         "pyproject-falls-to-poetry", "poetry-only", "pyproject-no-lock"],
)
def test_build_report_step_order(tmp_path, monkeypatch, files, ai_review, pep621, expected):
    events = []
    _install(monkeypatch, events, pep621=pep621)

    run_scan(_target(tmp_path, files), ai_review=ai_review)

    assert events == expected


def test_semgrep_error_stops_before_every_other_step(tmp_path, monkeypatch):
    events = []
    _install(monkeypatch, events, semgrep_error=True)

    with pytest.raises(ReportError, match=r"^Semgrep error: boom"):
        run_scan(_target(tmp_path, ["requirements.txt"]))

    assert events == ["semgrep"]


def test_dependency_error_stops_before_ignore_and_summary(tmp_path, monkeypatch):
    events = []
    _install(monkeypatch, events, dependency_error=True)

    with pytest.raises(ReportError, match=r"^Supply chain check error: boom"):
        run_scan(_target(tmp_path, ["requirements.txt"]))

    assert events == HEAD + TAIL + ["deps_requirements"]


def test_data_flow_between_steps(tmp_path, monkeypatch):
    seen = _install(monkeypatch, [], suppress=1)

    report = run_scan(_target(tmp_path, ["requirements.txt"]), ai_review=True)

    assert seen["capability_in"] == 3
    assert seen["ai_in"] == ["A", "C"]  # AI only sees what the capability filter kept
    assert seen["ignore_in"] == 4  # semgrep(2) + typosquat + supply chain
    assert seen["summary_in"] == 3  # summary is built AFTER ignore
    assert report["summary"]["suppressed_count"] == 1
    assert [f["category"] for f in report["findings"]] == [
        "Tool Poisoning", "Typosquatting / Shadow-Server", "Supply Chain",
    ]
