"""Manifest-vs-code comparison (P11-4): does manifest.json declare the tools the code registers?

Pure logic: reads the JSON manifest (MCPB format, https://github.com/modelcontextprotocol/mcpb)
and compares its tool names with names the caller extracted from the code. Imports no other
analyzer and no diff module. Scanned code is never executed.

Known limits: the manifest is optional and its `tools` list is not required to be complete by
the specification; tools registered dynamically (add_tool, low-level SDK) are invisible to the
caller's extraction, so a manifest-only tool can also just mean "registered in a way we cannot see".
"""

from __future__ import annotations

import json
from pathlib import Path

# Manifest server types whose code this scanner can actually read (Python via ast, node via tree-sitter).
_SCANNABLE_SERVER_TYPES = {"python", "uv", "node"}


def load_declared_tools(manifest_path: str | Path) -> dict | None:
    """Return {"tools", "generated", "server_type"} or None if there is nothing to compare.

    None for: manifests of servers that are neither Python nor node (e.g. binary), and manifests without a `tools` list (the field
    is optional, so its absence declares nothing). Raises OSError/ValueError on unreadable or
    invalid JSON; the caller decides how to handle that.
    """
    data = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return None

    server = data.get("server")
    server_type = server.get("type") if isinstance(server, dict) else None
    if server_type not in _SCANNABLE_SERVER_TYPES:
        return None

    tools = data.get("tools")
    if not isinstance(tools, list):
        return None

    names = {
        entry["name"]
        for entry in tools
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    }
    return {
        "tools": names,
        "generated": data.get("tools_generated") is True,
        # Lets the caller pick which source files to read: "node" -> TS/JS, else Python.
        "server_type": server_type,
    }


def compare_manifest_to_code(
    manifest_path: str | Path, declared: dict, code_tools: set[str]
) -> list[dict]:
    """Report rows for tools registered in code but undeclared (WARNING) and vice versa (INFO).

    A manifest with `tools_generated: true` announces extra tools, so undeclared code tools are
    expected there and not reported.
    """
    rows = []
    if not declared["generated"]:
        for name in sorted(code_tools - declared["tools"]):
            rows.append(
                _row(
                    manifest_path,
                    "WARNING",
                    f"Hidden tool candidate: tool '{name}' is registered in the code but not "
                    "declared in manifest.json. A user reading only the manifest would not "
                    "know it exists.",
                )
            )
    for name in sorted(declared["tools"] - code_tools):
        rows.append(
            _row(
                manifest_path,
                "INFO",
                f"Tool '{name}' is declared in manifest.json but no such registered tool was "
                "found in the code (outdated manifest, or registered in a way the scanner "
                "cannot see).",
            )
        )
    return rows


def _row(manifest_path: str | Path, severity: str, message: str) -> dict:
    return {
        "category": "Supply Chain",
        "file": str(manifest_path),
        "line": None,
        "severity": severity,
        "message": message,
    }
