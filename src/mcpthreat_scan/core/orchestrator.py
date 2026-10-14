"""Scan and diff orchestration; logic is migrated step by step."""

from __future__ import annotations

import os
from pathlib import Path

from mcpthreat_scan.analyzers.ai_review import AIReviewError, review_candidate
from mcpthreat_scan.analyzers.capability import filter_capability_mismatch_candidates
from mcpthreat_scan.analyzers.dependencies import (
    DependencyCheckError,
    check_package_lock_dependencies,
    check_poetry_lock_dependencies,
    check_pyproject_dependencies,
    check_requirements_file,
    has_pep621_dependencies,
    osv_scanner_installed,
)
from mcpthreat_scan.analyzers.manifest import compare_manifest_to_code, load_declared_tools
from mcpthreat_scan.analyzers.semgrep import SemgrepRunnerError, run_semgrep_rules
from mcpthreat_scan.analyzers.typosquat import check_declared_name, check_typosquat
from mcpthreat_scan.core.exceptions import ReportError
from mcpthreat_scan.core.models import VULNERABILITY_CATEGORIES
from mcpthreat_scan.diff.rugpull import diff_tool_schema_files
from mcpthreat_scan.diff.tool_schema import (
    extract_docstring_at_line,
    extract_handler_signature_at_line,
    extract_registered_tool_names,
    extract_return_text_at_line,
)
from mcpthreat_scan.diff.ts_tool_schema import (
    TS_JS_SUFFIXES,
    extract_ts_declared_server_name,
    extract_ts_description_at_line,
    extract_ts_registered_tool_names,
    extract_ts_return_text_at_line,
    ts_skip_reason,
)
from mcpthreat_scan.policy.ignore import apply_ignore_rules, load_ignore_rules


# Rule ID matched via substring check since Semgrep namespaces it.
_TOOL_POISONING_CANDIDATE_RULE_ID = "tool-poisoning-docstring-candidate"
# P11-3: same signal words, but on the text a handler returns instead of its docstring.
_TOOL_POISONING_OUTPUT_CANDIDATE_RULE_ID = "tool-poisoning-output-candidate"
# Same two checks for TypeScript/JavaScript (tool_poisoning_node.yaml).
_TS_DESCRIPTION_CANDIDATE_RULE_ID = "tool-poisoning-description-node-candidate"
_TS_OUTPUT_CANDIDATE_RULE_ID = "tool-poisoning-output-node-candidate"


def _extract_candidate_text(finding: dict) -> str | None:
    """Re-extract the flagged text: handler return text for an output rule, else the description."""
    rule_id = finding["rule_id"]
    if _TS_OUTPUT_CANDIDATE_RULE_ID in rule_id:
        return extract_ts_return_text_at_line(finding["file"], finding["line"])
    if _TS_DESCRIPTION_CANDIDATE_RULE_ID in rule_id:
        return extract_ts_description_at_line(finding["file"], finding["line"])
    if _TOOL_POISONING_OUTPUT_CANDIDATE_RULE_ID in rule_id:
        return extract_return_text_at_line(finding["file"], finding["line"])
    return extract_docstring_at_line(finding["file"], finding["line"])


def _apply_ai_review(semgrep_findings: list[dict]) -> list[dict]:
    """Run Layer-2 AI review on Tool Poisoning candidates; keep original if Layer 2 fails."""
    updated_findings = []
    for finding in semgrep_findings:
        if not any(
            rule_id in finding["rule_id"]
            for rule_id in (
                _TOOL_POISONING_CANDIDATE_RULE_ID,
                _TOOL_POISONING_OUTPUT_CANDIDATE_RULE_ID,
                _TS_DESCRIPTION_CANDIDATE_RULE_ID,
                _TS_OUTPUT_CANDIDATE_RULE_ID,
            )
        ):
            # Not a Tool Poisoning candidate; pass through unchanged.
            updated_findings.append(finding)
            continue

        candidate_text = _extract_candidate_text(finding)
        finding = dict(finding)  # Shallow copy to avoid mutating input.
        if candidate_text is None:
            # Could not re-extract the text; keep original candidate.
            updated_findings.append(finding)
            continue

        try:
            verdict = review_candidate(candidate_text)
        except AIReviewError as exc:
            # Layer 2 failure must not abort scan; add note to finding.
            finding["message"] = (
                f"{finding['message']} [Automatic layer-2 review not "
                f"possible: {exc}]"
            )
            updated_findings.append(finding)
            continue

        if verdict["suspicious"]:
            # AI confirmed: promote from WARNING (candidate) to ERROR (confirmed).
            finding["severity"] = "ERROR"
            finding["message"] = (
                "Tool Poisoning (layer-2 AI review CONFIRMED): "
                f"{verdict['reasoning']} (confidence: {verdict['confidence']:.2f})"
            )
        else:
            # AI cleared: keep in report for transparency, but mark as INFO.
            finding["severity"] = "INFO"
            finding["message"] = (
                "Tool Poisoning (layer-2 AI review: no tool poisoning detected, "
                f"candidate dismissed): {verdict['reasoning']} "
                f"(confidence: {verdict['confidence']:.2f})"
            )
        updated_findings.append(finding)
    return updated_findings


def _filter_capability_mismatch_candidates(semgrep_findings: list[dict]) -> list[dict]:
    """Drop Capability Mismatch candidates that already disclose the capability."""
    return filter_capability_mismatch_candidates(semgrep_findings, extract_handler_signature_at_line)


def _run_semgrep_stage(target: Path) -> list[dict]:
    """Run the Semgrep rules; translate runner failures into ReportError."""
    try:
        return run_semgrep_rules(target)
    except SemgrepRunnerError as exc:
        raise ReportError(f"Semgrep error: {exc}") from exc


def _run_dependency_stage(target: Path) -> list[dict]:
    """Supply-chain check for a scanned directory (Python and npm); returns report rows.

    Single files are never checked. Failures become ReportError.
    """
    if not target.is_dir():
        return []
    return _run_python_dependency_stage(target) + _run_npm_dependency_stage(target)


def _run_npm_dependency_stage(target: Path) -> list[dict]:
    """OSV check of package-lock.json in the scanned folder root (P12-4, external osv-scanner).

    A missing osv-scanner does not abort the scan: it becomes one INFO row saying the check was
    skipped, so a Node server is never silently reported as dependency-clean.
    """
    package_lock_path = target / "package-lock.json"
    if not package_lock_path.exists():
        return []

    if not osv_scanner_installed():
        return [
            {
                "category": "Supply Chain",
                "file": str(package_lock_path),
                "line": None,
                "severity": "INFO",
                "message": (
                    "npm dependency check skipped: osv-scanner is not installed or not on PATH "
                    "(https://google.github.io/osv-scanner/installation/)"
                ),
            }
        ]

    try:
        findings = check_package_lock_dependencies(package_lock_path)
    except DependencyCheckError as exc:
        raise ReportError(f"Supply chain check error: {exc}") from exc
    return _dependency_findings_to_report_rows(package_lock_path, findings, separator="@")


def _run_python_dependency_stage(target: Path) -> list[dict]:
    """Python part of the supply-chain check.

    Source priority: requirements.txt > PEP 621 pyproject.toml > poetry.lock.
    """

    requirements_path = target / "requirements.txt"
    pyproject_path = target / "pyproject.toml"
    poetry_lock_path = target / "poetry.lock"

    dependency_findings: list[dict] = []
    dependency_source_path: Path | None = None

    try:
        if requirements_path.exists():
            dependency_source_path = requirements_path
            dependency_findings = check_requirements_file(requirements_path)
        elif pyproject_path.exists() and has_pep621_dependencies(pyproject_path):
            dependency_source_path = pyproject_path
            dependency_findings = check_pyproject_dependencies(target)
        elif poetry_lock_path.exists():
            dependency_source_path = poetry_lock_path
            dependency_findings = check_poetry_lock_dependencies(poetry_lock_path)
    except DependencyCheckError as exc:
        raise ReportError(f"Supply chain check error: {exc}") from exc

    if dependency_source_path is None:
        return []
    return _dependency_findings_to_report_rows(dependency_source_path, dependency_findings)


# Folders that hold third-party code, never part of the scanned server itself.
_MANIFEST_SKIPPED_DIRS = {".venv", "venv", "node_modules", "site-packages"}


def _iter_ts_js_sources(root: Path) -> list[Path]:
    """TS/JS files of the server itself below root, sorted; third-party folders are never entered.

    .d.ts typing files are left out. Pruning while walking keeps a huge node_modules untouched.
    """
    found = []
    for directory, subdirs, filenames in os.walk(root):
        subdirs[:] = [d for d in subdirs if d not in _MANIFEST_SKIPPED_DIRS]
        for filename in filenames:
            path = Path(directory) / filename
            if path.suffix.lower() in TS_JS_SUFFIXES and not filename.lower().endswith(".d.ts"):
                found.append(path)
    return sorted(found)


def _skipped_ts_rows(paths: list[Path]) -> list[dict]:
    """One INFO row per TS/JS file the TypeScript checks did not parse (never a silent skip)."""
    rows = []
    for path in paths:
        if path.suffix.lower() not in TS_JS_SUFFIXES:
            continue
        try:
            reason = ts_skip_reason(path)
        except OSError:
            continue
        if reason:
            rows.append(
                {
                    "category": "Scan Coverage",
                    "file": str(path),
                    "line": None,
                    "severity": "INFO",
                    "message": (
                        "Not analyzed by the TypeScript checks (manifest, typosquat, rug-pull): "
                        f"{reason}. Semgrep rules may still have scanned it."
                    ),
                }
            )
    return rows


def _check_ts_typosquat(path: Path) -> list[dict]:
    """Typosquatting check for one TS/JS file: extract the server name, then compare it."""
    declared = extract_ts_declared_server_name(path)
    if declared is None:
        return []
    name, line = declared
    return check_declared_name(path, name, line)


def _run_typosquat_stage(target: Path) -> list[dict]:
    """Typosquatting check on one file or all .py/.ts/.js files of a folder (unreadable skipped)."""
    if target.is_file():
        paths = [target]
    else:
        paths = sorted(target.rglob("*.py")) + _iter_ts_js_sources(target)
    findings: list[dict] = []
    for path in paths:
        try:
            if path.suffix.lower() in TS_JS_SUFFIXES:
                findings.extend(_check_ts_typosquat(path))
            else:
                findings.extend(check_typosquat(path))
        except (OSError, SyntaxError):
            continue
    return findings


def _source_files_of_manifest(
    manifest_path: Path, all_manifest_dirs: list[Path], *, node: bool
) -> list[Path]:
    """Source files that belong to this manifest: below its folder, not below a nested manifest.

    node=True selects TS/JS files, otherwise .py files.
    """
    manifest_dir = manifest_path.parent
    nested_dirs = [d for d in all_manifest_dirs if d != manifest_dir and manifest_dir in d.parents]
    candidates = _iter_ts_js_sources(manifest_dir) if node else sorted(manifest_dir.rglob("*.py"))
    files = []
    for path in candidates:
        if _MANIFEST_SKIPPED_DIRS.intersection(path.relative_to(manifest_dir).parts):
            continue
        if any(nested in path.parents for nested in nested_dirs):
            continue
        files.append(path)
    return files


def _run_manifest_stage(target: Path) -> list[dict]:
    """Compare every manifest.json in a scanned folder with the tools its code registers (P11-4).

    Single files and folders without a comparable manifest yield nothing. Unreadable or invalid
    manifests and unparsable .py files are skipped, not fatal.
    """
    if not target.is_dir():
        return []

    manifest_paths = sorted(target.rglob("manifest.json"))
    manifest_dirs = [path.parent for path in manifest_paths]
    rows: list[dict] = []
    for manifest_path in manifest_paths:
        try:
            declared = load_declared_tools(manifest_path)
        except (OSError, ValueError):
            continue
        if declared is None:
            continue

        is_node = declared["server_type"] == "node"
        extract_names = extract_ts_registered_tool_names if is_node else extract_registered_tool_names
        code_tools: set[str] = set()
        for source_file in _source_files_of_manifest(manifest_path, manifest_dirs, node=is_node):
            try:
                code_tools |= extract_names(source_file)
            except (OSError, SyntaxError, ValueError):
                continue
        rows.extend(compare_manifest_to_code(manifest_path, declared, code_tools))
    return rows


def _apply_ignore_stage(findings: list[dict], ignore_file: str | Path) -> tuple[list[dict], int]:
    """Drop findings covered by the ignore file; return (kept findings, suppressed count)."""
    ignore_rules = load_ignore_rules(ignore_file)
    return apply_ignore_rules(findings, ignore_rules)


# Severity for rug-pull changes: visible changes (tool add/remove, params, docstring)
# stay at INFO/WARNING since a human would notice them in a diff. Hidden behavior
# changes (identical signature/docstring, only body changed) are ERROR.
_RUGPULL_SEVERITY_BY_CHANGE = {
    "tool_added": "INFO",
    "tool_removed": "INFO",
    "parameters_changed": "WARNING",
    "docstring_changed": "WARNING",
    "behavior_changed_hidden": "ERROR",
}


def _rugpull_finding_message(finding: dict) -> str:
    """Format a rug-pull finding as human-readable message."""
    change = finding["change"]
    tool = finding["tool"]

    if change == "tool_added":
        return f"Tool Poisoning: New tool '{tool}' was added in the new version."
    if change == "tool_removed":
        return f"Tool Poisoning: Tool '{tool}' is no longer present in the new version."
    if change == "parameters_changed":
        detail_text = ", ".join(
            f"{item['parameter']} ({item['change']})" for item in finding["details"]
        )
        return f"Tool Poisoning: Parameters of tool '{tool}' changed: {detail_text}."
    if change == "docstring_changed":
        return f"Tool Poisoning: Docstring/tool description of tool '{tool}' changed."
    # behavior_changed_hidden: signature and docstring unchanged, but body changed.
    return (
        f"Tool Poisoning (suspected rug pull): Tool '{tool}' has identical parameters and "
        "an identical docstring in both versions, but the function body has "
        "changed. A human comparing only signature/documentation would NOT "
        "notice this change."
    )


def _rugpull_findings_to_report_rows(
    after_path: Path, rugpull_findings: list[dict]
) -> list[dict]:
    """Convert rug-pull diff output to unified finding shape (line=None, file=after_path)."""
    return [
        {
            "category": "Tool Poisoning",
            "file": str(after_path),
            "line": None,
            "severity": _RUGPULL_SEVERITY_BY_CHANGE[finding["change"]],
            "message": _rugpull_finding_message(finding),
        }
        for finding in rugpull_findings
    ]


def _run_diff_stage(before: Path, after: Path) -> list[dict]:
    """Rug-pull diff of two file versions; returns report rows.

    Unreadable or unparsable files (OSError/SyntaxError) become ReportError.
    """
    try:
        rugpull_findings = diff_tool_schema_files(before, after)
    except (OSError, SyntaxError) as exc:
        raise ReportError(f"Rug-pull diff error: {exc}") from exc

    # A skipped file would otherwise read as "no change"; say that it was not compared.
    return _rugpull_findings_to_report_rows(after, rugpull_findings) + _skipped_ts_rows(
        [before, after]
    )


def _dependency_findings_to_report_rows(
    source_path: Path, dependency_findings: list[dict], separator: str = "=="
) -> list[dict]:
    """Convert dependency check output to unified finding shape (line=None, severity=ERROR)."""
    rows = []
    for dependency in dependency_findings:
        vulnerability_ids = ", ".join(v["id"] for v in dependency["vulnerabilities"])
        rows.append(
            {
                "category": "Supply Chain",
                "file": str(source_path),
                "line": None,
                "severity": "ERROR",
                "message": f"{dependency['name']}{separator}{dependency['version']}: {vulnerability_ids}",
            }
        )
    return rows


def _semgrep_findings_to_report_rows(semgrep_findings: list[dict]) -> list[dict]:
    """Convert Semgrep findings to unified report-row shape."""
    return [
        {
            "category": finding["category"],
            "file": finding["file"],
            "line": finding["line"],
            "severity": finding["severity"],
            "message": finding["message"],
        }
        for finding in semgrep_findings
    ]


def _build_summary(findings: list[dict]) -> dict:
    """Compute category-coverage summary score."""
    categories_with_finding = sorted(
        {finding["category"] for finding in findings if finding["category"] in VULNERABILITY_CATEGORIES}
    )
    return {
        "categories_checked": len(VULNERABILITY_CATEGORIES),
        "categories_without_finding": len(VULNERABILITY_CATEGORIES) - len(categories_with_finding),
        "categories_with_finding": categories_with_finding,
    }


def run_scan(
    target_path: str | Path,
    *,
    ai_review: bool = False,
    ignore_file: str | Path = ".mcpscannerignore",
) -> dict:
    """Run full scan (Semgrep + OSV if in directory) and return structured report."""
    target = Path(target_path)

    semgrep_findings = _run_semgrep_stage(target)

    semgrep_findings = _filter_capability_mismatch_candidates(semgrep_findings)

    if ai_review:
        semgrep_findings = _apply_ai_review(semgrep_findings)

    findings = _semgrep_findings_to_report_rows(semgrep_findings)
    findings.extend(_run_typosquat_stage(target))

    findings.extend(_run_dependency_stage(target))
    findings.extend(_run_manifest_stage(target))
    findings.extend(_skipped_ts_rows([target] if target.is_file() else _iter_ts_js_sources(target)))

    findings, suppressed_count = _apply_ignore_stage(findings, ignore_file)

    summary = _build_summary(findings)
    if suppressed_count:
        summary["suppressed_count"] = suppressed_count

    return {
        "target": str(target),
        "findings": findings,
        "summary": summary,
    }


def run_diff(before_path: str | Path, after_path: str | Path) -> dict:
    """Compare two file versions for rug-pull changes; return report in same shape as run_scan()."""
    before = Path(before_path)
    after = Path(after_path)

    findings = _run_diff_stage(before, after)

    return {
        "target": f"{before} -> {after}",
        "findings": findings,
        "summary": _build_summary(findings),
    }
