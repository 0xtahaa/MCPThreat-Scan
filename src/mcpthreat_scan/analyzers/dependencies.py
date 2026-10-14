"""Supply Chain: check dependencies against OSV.

Python: pip-audit --no-deps (no installation, just metadata lookup).
npm (P12-4): the external osv-scanner program reads package-lock.json (no npm install, so no
install scripts of the scanned project ever run).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path


class DependencyCheckError(RuntimeError):
    """pip-audit could not run or produced no result."""


def _parse_pip_audit_result(result: subprocess.CompletedProcess) -> list[dict]:
    """Shared JSON parsing/dedup logic for any pip-audit invocation."""
    # Exit 0 = no vulns, 1 = vulns found. Any other code is a tool failure.
    if result.returncode not in (0, 1):
        raise DependencyCheckError(
            f"pip-audit failed (exit {result.returncode}): {result.stderr.strip()}"
        )

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise DependencyCheckError(
            f"pip-audit returned no valid JSON output: {exc}"
        ) from exc

    findings = []
    for dependency in data.get("dependencies", []):
        vulns = dependency.get("vulns", [])
        if not vulns:
            continue

        # Deduplicate by vulnerability ID.
        seen_ids: set[str] = set()
        deduped_vulns = []
        for vuln in vulns:
            if vuln["id"] in seen_ids:
                continue
            seen_ids.add(vuln["id"])
            deduped_vulns.append(
                {
                    "id": vuln["id"],
                    "aliases": vuln.get("aliases", []),
                    "fix_versions": vuln.get("fix_versions", []),
                    "description": vuln.get("description", ""),
                }
            )

        findings.append(
            {
                "name": dependency["name"],
                "version": dependency["version"],
                "vulnerabilities": deduped_vulns,
            }
        )

    return findings


def check_requirements_file(requirements_path: str | Path) -> list[dict]:
    """Check requirements.txt for known vulnerabilities via OSV."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip_audit",
            "-r",
            str(requirements_path),
            "--no-deps",
            "-s",
            "osv",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
    )
    return _parse_pip_audit_result(result)


def has_pep621_dependencies(pyproject_path: str | Path) -> bool:
    """Check whether pyproject.toml declares dependencies the PEP 621 way ([project.dependencies])."""
    with open(pyproject_path, "rb") as f:
        data = tomllib.load(f)
    return "dependencies" in data.get("project", {})


def check_pyproject_dependencies(project_dir: str | Path) -> list[dict]:
    """Check a PEP 621 pyproject.toml project for known vulnerabilities via OSV.

    pip-audit resolves declared dependencies itself (dry-run pip install into a
    throwaway venv) - --no-deps is not supported in this mode.
    """
    result = subprocess.run(
        [sys.executable, "-m", "pip_audit", str(project_dir), "-s", "osv", "--format", "json"],
        capture_output=True,
        text=True,
    )
    return _parse_pip_audit_result(result)


def check_dependency_list(dependencies: list[str]) -> list[dict]:
    """Check a list of "package==version" strings by writing to temp requirements.txt."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    ) as tmp_file:
        tmp_file.write("\n".join(dependencies) + "\n")
        tmp_path = tmp_file.name

    try:
        return check_requirements_file(tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def check_poetry_lock_dependencies(poetry_lock_path: str | Path) -> list[dict]:
    """Check a poetry.lock file for known vulnerabilities via OSV (already-resolved exact versions)."""
    with open(poetry_lock_path, "rb") as f:
        lock_data = tomllib.load(f)

    dependencies = [
        f"{package['name']}=={package['version']}"
        for package in lock_data.get("package", [])
    ]
    return check_dependency_list(dependencies)


def osv_scanner_installed() -> bool:
    """True if the external osv-scanner program is on PATH (needed for the npm check)."""
    return shutil.which("osv-scanner") is not None


def check_package_lock_dependencies(package_lock_path: str | Path) -> list[dict]:
    """Check a package-lock.json for known vulnerabilities via the external osv-scanner (P12-4).

    Same result shape as the Python checks. Raises DependencyCheckError if the program is not on
    PATH or fails. Exit 0 = clean, 1 = vulnerabilities found, 128 = no packages found (nothing to
    report); anything else is a tool failure.
    """
    executable = shutil.which("osv-scanner")
    if executable is None:
        raise DependencyCheckError(
            "osv-scanner is not installed or not on PATH "
            "(https://google.github.io/osv-scanner/installation/)"
        )

    result = subprocess.run(
        [executable, "scan", "-L", str(package_lock_path), "--format", "json"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 128:
        return []
    if result.returncode not in (0, 1):
        raise DependencyCheckError(
            f"osv-scanner failed (exit {result.returncode}): {result.stderr.strip()}"
        )

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise DependencyCheckError(f"osv-scanner returned no valid JSON output: {exc}") from exc

    packages: dict[tuple[str, str], dict] = {}
    for scan_result in data.get("results", []):
        for entry in scan_result.get("packages", []):
            vulnerabilities = entry.get("vulnerabilities", [])
            if not vulnerabilities:
                continue
            package = entry["package"]
            finding = packages.setdefault(
                (package["name"], package["version"]),
                {"name": package["name"], "version": package["version"], "vulnerabilities": []},
            )
            known_ids = {vuln["id"] for vuln in finding["vulnerabilities"]}
            for vuln in vulnerabilities:
                if vuln["id"] not in known_ids:
                    known_ids.add(vuln["id"])
                    finding["vulnerabilities"].append(
                        {
                            "id": vuln["id"],
                            "aliases": vuln.get("aliases", []),
                            "fix_versions": [],
                            "description": vuln.get("summary", ""),
                        }
                    )
    return list(packages.values())
