"""Typosquatting/shadow-server heuristic: compares the declared server name
against a curated list of known, established MCP servers (P11-2).

Purely static string comparison (edit distance via difflib), no network
access, no runtime tracing - fits the zero-execution principle.
"""

from __future__ import annotations

import ast
import difflib
import json
from pathlib import Path

DEFAULT_KNOWN_SERVERS_PATH = (
    Path(__file__).parent.parent / "resources" / "known_mcp_servers.json"
)
SIMILARITY_THRESHOLD = 0.7

_SERVER_CONSTRUCTOR_NAMES = {"FastMCP", "Server"}


def load_known_servers(path: str | Path = DEFAULT_KNOWN_SERVERS_PATH) -> list[str]:
    """Kuratierte Liste bekannter/etablierter MCP-Server-Namen laden."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return data["servers"]


def extract_declared_server_name(path: str | Path) -> tuple[str, int] | None:
    """Find the first FastMCP(...)/Server(...) call and return (name, line)."""
    source = Path(path).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        constructor_name = None
        if isinstance(func, ast.Name):
            constructor_name = func.id
        elif isinstance(func, ast.Attribute):
            constructor_name = func.attr
        if constructor_name not in _SERVER_CONSTRUCTOR_NAMES:
            continue

        for keyword in node.keywords:
            if (
                keyword.arg == "name"
                and isinstance(keyword.value, ast.Constant)
                and isinstance(keyword.value.value, str)
            ):
                return keyword.value.value, node.lineno

        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            return node.args[0].value, node.lineno

    return None


def _normalize(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def find_typosquat_candidate(name: str, known_servers: list[str]) -> dict | None:
    """Find the closest known name - only for near matches, not for an exact hit."""
    normalized_name = _normalize(name)
    best_match = None
    best_ratio = 0.0

    for known in known_servers:
        ratio = difflib.SequenceMatcher(None, normalized_name, _normalize(known)).ratio()
        if ratio > best_ratio:
            best_ratio = ratio
            best_match = known

    if best_match is None or best_ratio >= 1.0 or best_ratio < SIMILARITY_THRESHOLD:
        return None

    return {"matched_name": best_match, "similarity": best_ratio}


def check_typosquat(
    path: str | Path,
    *,
    known_servers_path: str | Path = DEFAULT_KNOWN_SERVERS_PATH,
) -> list[dict]:
    """Check one Python file for a typosquatting candidate."""
    declared = extract_declared_server_name(path)
    if declared is None:
        return []
    name, line = declared
    return check_declared_name(path, name, line, known_servers_path=known_servers_path)


def check_declared_name(
    path: str | Path,
    name: str,
    line: int,
    *,
    known_servers_path: str | Path = DEFAULT_KNOWN_SERVERS_PATH,
) -> list[dict]:
    """Compare an already extracted server name (any language) with the known servers.

    The orchestrator extracts the name (Python via ast, TypeScript via tree-sitter) and passes it
    here, so this analyzer stays free of any other module.
    """
    known_servers = load_known_servers(known_servers_path)
    candidate = find_typosquat_candidate(name, known_servers)
    if candidate is None:
        return []

    similarity_pct = round(candidate["similarity"] * 100)
    return [
        {
            "category": "Typosquatting / Shadow-Server",
            "file": str(path),
            "line": line,
            "severity": "WARNING",
            "message": (
                f"Server name '{name}' is very similar to the known server "
                f"'{candidate['matched_name']}' ({similarity_pct}% similarity) - "
                "candidate, not a hard verdict. Check whether the name is "
                "deliberately deceptive."
            ),
        }
    ]
