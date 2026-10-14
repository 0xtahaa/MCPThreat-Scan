"""Tests for P2-6: Supply Chain OSV dependency check (via pip-audit).

Known-vulnerable package test makes real network call to OSV database."""

import json
from types import SimpleNamespace

from mcpthreat_scan.analyzers.dependencies import (
    check_dependency_list,
    check_poetry_lock_dependencies,
    check_pyproject_dependencies,
    check_requirements_file,
    has_pep621_dependencies,
)


def test_known_vulnerable_package_is_flagged():
    """Live OSV test: urllib3==1.26.4 must report CVE-2021-33503."""
    findings = check_dependency_list(["urllib3==1.26.4"])

    assert len(findings) == 1
    assert findings[0]["name"] == "urllib3"
    assert findings[0]["version"] == "1.26.4"
    assert len(findings[0]["vulnerabilities"]) > 0
    all_aliases = {
        alias
        for vuln in findings[0]["vulnerabilities"]
        for alias in vuln["aliases"]
    }
    assert "CVE-2021-33503" in all_aliases


def test_pinned_package_without_findings_is_omitted(monkeypatch, tmp_path):
    """Package with no vulns must not appear in results."""
    fake_stdout = json.dumps(
        {
            "dependencies": [
                {"name": "harmless-pkg", "version": "1.0.0", "vulns": []},
            ]
        }
    )
    monkeypatch.setattr(
        "mcpthreat_scan.analyzers.dependencies.subprocess.run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout=fake_stdout, stderr=""),
    )

    req_file = tmp_path / "requirements.txt"
    req_file.write_text("harmless-pkg==1.0.0\n", encoding="utf-8")

    assert check_requirements_file(req_file) == []


# ============================================================================
# P10-4: pyproject.toml (PEP 621) and poetry.lock support alongside
# requirements.txt.
# ============================================================================


def test_pyproject_pep621_project_with_known_vulnerable_dependency_is_flagged(tmp_path):
    """Live OSV test: PEP 621 pyproject.toml with pinned urllib3==1.26.4 must report CVE-2021-33503."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "test-project"\nversion = "0.1.0"\n'
        'dependencies = ["urllib3==1.26.4"]\n',
        encoding="utf-8",
    )

    findings = check_pyproject_dependencies(tmp_path)

    assert len(findings) == 1
    assert findings[0]["name"] == "urllib3"
    assert findings[0]["version"] == "1.26.4"
    all_aliases = {alias for vuln in findings[0]["vulnerabilities"] for alias in vuln["aliases"]}
    assert "CVE-2021-33503" in all_aliases


def test_has_pep621_dependencies_true_for_project_table(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "x"\nversion = "0.1.0"\ndependencies = ["urllib3==1.26.4"]\n',
        encoding="utf-8",
    )

    assert has_pep621_dependencies(pyproject) is True


def test_has_pep621_dependencies_false_for_poetry_style_table(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[tool.poetry]\nname = "x"\nversion = "0.1.0"\n\n'
        '[tool.poetry.dependencies]\npython = "^3.10"\nurllib3 = "1.26.4"\n',
        encoding="utf-8",
    )

    assert has_pep621_dependencies(pyproject) is False


def test_poetry_lock_with_known_vulnerable_dependency_is_flagged(tmp_path):
    """Live OSV test: poetry.lock with urllib3==1.26.4 must report CVE-2021-33503; harmless package omitted."""
    poetry_lock = tmp_path / "poetry.lock"
    poetry_lock.write_text(
        '[[package]]\nname = "urllib3"\nversion = "1.26.4"\n\n'
        '[[package]]\nname = "six"\nversion = "1.16.0"\n',
        encoding="utf-8",
    )

    findings = check_poetry_lock_dependencies(poetry_lock)

    assert len(findings) == 1
    assert findings[0]["name"] == "urllib3"
    all_aliases = {alias for vuln in findings[0]["vulnerabilities"] for alias in vuln["aliases"]}
    assert "CVE-2021-33503" in all_aliases
