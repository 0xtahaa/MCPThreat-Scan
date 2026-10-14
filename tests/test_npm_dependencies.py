"""Tests for P12-4: npm dependency check via the external osv-scanner (all subprocess calls mocked)."""

import json
import subprocess

import pytest

from mcpthreat_scan.analyzers import dependencies
from mcpthreat_scan.analyzers.dependencies import (
    DependencyCheckError,
    check_package_lock_dependencies,
    osv_scanner_installed,
)
from mcpthreat_scan.core import orchestrator
from mcpthreat_scan.core.exceptions import ReportError

OSV_JSON = {
    "results": [
        {
            "source": {"path": "package-lock.json", "type": "lockfile"},
            "packages": [
                {
                    "package": {"name": "left-pad", "version": "1.0.0", "ecosystem": "npm"},
                    "vulnerabilities": [
                        {"id": "GHSA-aaaa", "aliases": ["CVE-1"], "summary": "bad"},
                        {"id": "GHSA-aaaa", "aliases": ["CVE-1"]},
                        {"id": "GHSA-bbbb"},
                    ],
                },
                {"package": {"name": "safe", "version": "2.0.0", "ecosystem": "npm"}, "vulnerabilities": []},
            ],
        }
    ]
}


def _fake_run(returncode=1, stdout=None, stderr=""):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, returncode, json.dumps(stdout) if stdout is not None else "", stderr)

    return run, calls


def _installed(monkeypatch):
    monkeypatch.setattr(dependencies.shutil, "which", lambda name: "/bin/osv-scanner")


def test_check_parses_and_deduplicates_vulnerable_packages(monkeypatch):
    _installed(monkeypatch)
    run, calls = _fake_run(1, OSV_JSON)
    monkeypatch.setattr(dependencies.subprocess, "run", run)

    findings = check_package_lock_dependencies("package-lock.json")

    assert calls == [["/bin/osv-scanner", "scan", "-L", "package-lock.json", "--format", "json"]]
    assert findings == [
        {
            "name": "left-pad",
            "version": "1.0.0",
            "vulnerabilities": [
                {"id": "GHSA-aaaa", "aliases": ["CVE-1"], "fix_versions": [], "description": "bad"},
                {"id": "GHSA-bbbb", "aliases": [], "fix_versions": [], "description": ""},
            ],
        }
    ]


def test_check_returns_nothing_for_clean_lockfile_and_for_no_packages(monkeypatch):
    _installed(monkeypatch)
    monkeypatch.setattr(dependencies.subprocess, "run", _fake_run(0, {"results": []})[0])
    assert check_package_lock_dependencies("p.json") == []

    monkeypatch.setattr(dependencies.subprocess, "run", _fake_run(128, None, "no packages")[0])
    assert check_package_lock_dependencies("p.json") == []


def test_check_raises_when_osv_scanner_is_missing_and_installed_check_reflects_it(monkeypatch):
    monkeypatch.setattr(dependencies.shutil, "which", lambda name: None)

    assert osv_scanner_installed() is False
    with pytest.raises(DependencyCheckError):
        check_package_lock_dependencies("p.json")

    _installed(monkeypatch)
    assert osv_scanner_installed() is True


@pytest.mark.parametrize("returncode,stdout", [(127, None), (0, None)])
def test_check_raises_on_tool_failure_or_invalid_json(monkeypatch, returncode, stdout):
    _installed(monkeypatch)
    monkeypatch.setattr(dependencies.subprocess, "run", _fake_run(returncode, stdout, "boom")[0])

    with pytest.raises(DependencyCheckError):
        check_package_lock_dependencies("p.json")


def test_npm_stage_yields_nothing_without_package_lock(tmp_path):
    assert orchestrator._run_npm_dependency_stage(tmp_path) == []


def test_npm_stage_reports_vulnerabilities_as_supply_chain_errors(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(orchestrator, "osv_scanner_installed", lambda: True)
    monkeypatch.setattr(
        orchestrator, "check_package_lock_dependencies",
        lambda path: [{"name": "left-pad", "version": "1.0.0", "vulnerabilities": [{"id": "GHSA-aaaa"}]}],
    )

    (row,) = orchestrator._run_npm_dependency_stage(tmp_path)

    assert (row["category"], row["severity"], row["line"]) == ("Supply Chain", "ERROR", None)
    assert row["message"] == "left-pad@1.0.0: GHSA-aaaa"
    assert row["file"] == str(tmp_path / "package-lock.json")


def test_npm_stage_reports_skipped_check_as_info_when_osv_scanner_missing(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(orchestrator, "osv_scanner_installed", lambda: False)
    monkeypatch.setattr(
        orchestrator, "check_package_lock_dependencies",
        lambda path: pytest.fail("must not run without osv-scanner"),
    )

    (row,) = orchestrator._run_npm_dependency_stage(tmp_path)

    assert row["severity"] == "INFO" and row["category"] == "Supply Chain"
    assert row["message"].startswith("npm dependency check skipped: osv-scanner is not installed")


def test_npm_stage_turns_other_failures_into_report_error(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(orchestrator, "osv_scanner_installed", lambda: True)

    def failing(path):
        raise DependencyCheckError("osv-scanner failed")

    monkeypatch.setattr(orchestrator, "check_package_lock_dependencies", failing)

    with pytest.raises(ReportError):
        orchestrator._run_npm_dependency_stage(tmp_path)


def test_dependency_stage_combines_python_and_npm_rows(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("x==1\n", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(orchestrator, "osv_scanner_installed", lambda: True)
    monkeypatch.setattr(
        orchestrator, "check_requirements_file",
        lambda path: [{"name": "x", "version": "1", "vulnerabilities": [{"id": "PYSEC-1"}]}],
    )
    monkeypatch.setattr(
        orchestrator, "check_package_lock_dependencies",
        lambda path: [{"name": "y", "version": "2", "vulnerabilities": [{"id": "GHSA-1"}]}],
    )

    messages = [row["message"] for row in orchestrator._run_dependency_stage(tmp_path)]

    assert messages == ["x==1: PYSEC-1", "y@2: GHSA-1"]
