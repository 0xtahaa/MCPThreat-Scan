"""Run Semgrep against target, parse JSON output into normalized finding dicts."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


# Packaged rules, resolved relative to this module so the scan does not depend on the working
# directory (same approach as the known-servers list). Semgrep needs a real directory, which a
# regular installation provides; the check_id prefix Semgrep derives from this path varies.
DEFAULT_RULES_DIR = Path(__file__).parent.parent / "resources" / "rules"


class SemgrepRunnerError(RuntimeError):
    """Semgrep tool failed to run."""


def _find_semgrep_executable() -> str:
    """Locate semgrep executable in project venv, fall back to system PATH."""
    script_name = "semgrep.exe" if os.name == "nt" else "semgrep"
    sibling_path = Path(sys.executable).with_name(script_name)
    if sibling_path.exists():
        return str(sibling_path)

    found_on_path = shutil.which("semgrep")
    if found_on_path is not None:
        return found_on_path

    raise SemgrepRunnerError(
        "Could not find the semgrep command line. Is it installed in this "
        "environment? (pip install -r requirements.txt)"
    )


def run_semgrep_rules(
    target_path: str | Path,
    *,
    rules_dir: str | Path | None = None,
) -> list[dict]:
    """Scan target with all rules in rules_dir (default: packaged rules); return findings dicts."""
    if rules_dir is None:
        rules_dir = DEFAULT_RULES_DIR
        if not rules_dir.is_dir():
            raise SemgrepRunnerError(f"Rules directory not found: {rules_dir}")

    semgrep_executable = _find_semgrep_executable()

    result = subprocess.run(
        [
            semgrep_executable,
            "--config",
            str(rules_dir),
            "--json",
            "--quiet",
            str(target_path),
        ],
        capture_output=True,
        text=True,
    )

    # Exit 0 = no findings, 1 = findings found. Other codes indicate tool failure.
    if result.returncode not in (0, 1):
        raise SemgrepRunnerError(
            f"semgrep failed (exit {result.returncode}): "
            f"{result.stderr.strip()}"
        )

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SemgrepRunnerError(
            f"semgrep returned no valid JSON output: {exc}"
        ) from exc

    findings = []
    # Parse results: each match has metadata (category, severity, message) from rules/*.yaml.
    for match in data.get("results", []):
        extra = match.get("extra", {})
        metadata = extra.get("metadata", {})
        findings.append(
            {
                "file": match["path"],
                "line": match["start"]["line"],
                "rule_id": match["check_id"],
                "category": metadata.get("category"),
                "severity": extra.get("severity"),
                "message": extra.get("message", "").strip(),
            }
        )
    return findings
