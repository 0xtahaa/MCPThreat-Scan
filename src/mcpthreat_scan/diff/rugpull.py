"""Version comparison for rug-pull detection: compare tool schemas between file versions.

Detects silent behavior changes (identical signature/docstring, different body),
which are invisible in normal diffs but indicate a rug-pull attack.
"""

from __future__ import annotations

from pathlib import Path

from mcpthreat_scan.diff.tool_schema import extract_tool_schemas
from mcpthreat_scan.diff.ts_tool_schema import TS_JS_SUFFIXES, extract_ts_tool_schemas


def _diff_parameters(before_params: list[dict], after_params: list[dict]) -> list[dict]:
    """Compare function parameters; return list of {"parameter", "change", ...} dicts."""
    # Index by name to detect reordering and per-parameter changes.
    before_by_name = {p["name"]: p for p in before_params}
    after_by_name = {p["name"]: p for p in after_params}

    changes = []
    # Removed parameters.
    for name in sorted(set(before_by_name) - set(after_by_name)):
        changes.append({"parameter": name, "change": "removed"})
    # Added parameters.
    for name in sorted(set(after_by_name) - set(before_by_name)):
        changes.append({"parameter": name, "change": "added"})
    # Existing parameters that changed (kind or default).
    for name in sorted(set(before_by_name) & set(after_by_name)):
        before_param = before_by_name[name]
        after_param = after_by_name[name]
        if before_param != after_param:
            changes.append(
                {
                    "parameter": name,
                    "change": "modified",
                    "before": before_param,
                    "after": after_param,
                }
            )
    return changes


def diff_tool_schemas(before: list[dict], after: list[dict]) -> list[dict]:
    """Compare two tool schemas, return findings for added/removed/changed/behavior_changed_hidden."""
    # Index by name to handle reordering and direct lookup.
    before_by_name = {schema["name"]: schema for schema in before}
    after_by_name = {schema["name"]: schema for schema in after}

    findings = []

    # Removed tools.
    for name in sorted(set(before_by_name) - set(after_by_name)):
        findings.append({"tool": name, "change": "tool_removed"})

    # Added tools.
    for name in sorted(set(after_by_name) - set(before_by_name)):
        findings.append({"tool": name, "change": "tool_added"})

    # Existing tools: check parameters, docstring, and code body.
    for name in sorted(set(before_by_name) & set(after_by_name)):
        before_schema = before_by_name[name]
        after_schema = after_by_name[name]

        param_diff = _diff_parameters(before_schema["parameters"], after_schema["parameters"])
        if param_diff:
            findings.append(
                {"tool": name, "change": "parameters_changed", "details": param_diff}
            )

        docstring_changed = before_schema["docstring"] != after_schema["docstring"]
        if docstring_changed:
            findings.append(
                {
                    "tool": name,
                    "change": "docstring_changed",
                    "details": {
                        "before": before_schema["docstring"],
                        "after": after_schema["docstring"],
                    },
                }
            )

        # Hidden behavior change: body changed but signature/docstring identical.
        # Only report when no other changes already explain it.
        if (
            before_schema["body_hash"] != after_schema["body_hash"]
            and not param_diff
            and not docstring_changed
        ):
            findings.append({"tool": name, "change": "behavior_changed_hidden"})

    return findings


def _extract_schemas_by_suffix(path: str | Path) -> list[dict]:
    """Pick the extractor by file extension: .ts/.js family via tree-sitter, else Python AST."""
    if Path(path).suffix.lower() in TS_JS_SUFFIXES:
        # Tools whose name is not a plain string cannot be matched across versions; leave them out.
        return [s for s in extract_ts_tool_schemas(path) if s["name"] is not None]
    return extract_tool_schemas(path)


def diff_tool_schema_files(before_path: str | Path, after_path: str | Path) -> list[dict]:
    """Extract two files (Python or TypeScript/JavaScript) and compare them."""
    return diff_tool_schemas(
        _extract_schemas_by_suffix(before_path), _extract_schemas_by_suffix(after_path)
    )
