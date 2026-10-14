"""Extract tool schemas (name, parameters, docstring, body hash) from Python files via AST.

Parse, never execute. Supports nested tool functions (those with @*.tool() decorator)
for real-world MCP servers.
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

# Alias for both sync and async function definitions.
FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


def _extract_parameters(args: ast.arguments) -> list[dict]:
    """Convert AST arguments to list of dicts: {name, kind, default}."""
    parameters = []

    # Positional parameters (including position-only before "/").
    positional = list(args.posonlyargs) + list(args.args)

    # Build default value lookup: args.defaults only covers the last N positional args.
    defaults = list(args.defaults)
    num_without_default = len(positional) - len(defaults)
    default_by_index = {
        num_without_default + i: default for i, default in enumerate(defaults)
    }
    for index, arg in enumerate(positional):
        default = default_by_index.get(index)
        parameters.append(
            {
                "name": arg.arg,
                "kind": "positional",
                "default": ast.unparse(default) if default is not None else None,
            }
        )

    if args.vararg is not None:
        parameters.append({"name": args.vararg.arg, "kind": "vararg", "default": None})

    # Keyword-only parameters (after bare "*").
    for arg, default in zip(args.kwonlyargs, args.kw_defaults):
        parameters.append(
            {
                "name": arg.arg,
                "kind": "keyword_only",
                "default": ast.unparse(default) if default is not None else None,
            }
        )

    if args.kwarg is not None:
        parameters.append({"name": args.kwarg.arg, "kind": "kwarg", "default": None})

    return parameters


def _body_hash(node: FunctionNode, docstring: str | None) -> str:
    """Compute SHA-256 fingerprint of function body (excluding docstring and signature)."""
    body = node.body
    # Skip docstring (first statement) if present; it's compared separately.
    if docstring is not None and body and isinstance(body[0], ast.Expr):
        body = body[1:]
    # Dump AST structure without field annotations for stability.
    dumped = "\n".join(ast.dump(stmt, annotate_fields=False) for stmt in body)
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest()


def _is_tool_decorated(node: FunctionNode) -> bool:
    """Check if function has @*.tool or @*.tool() decorator."""
    for decorator in node.decorator_list:
        target = decorator
        # Unwrap Call nodes: @mcp.tool() -> Attribute "tool".
        if isinstance(target, ast.Call):
            target = target.func
        if isinstance(target, ast.Attribute) and target.attr == "tool":
            return True
    return False


def _iter_relevant_functions(tree: ast.Module):
    """Yield functions to extract: all top-level, plus nested ones with @*.tool decorator.

    Top-level: always included (preserves original P4-1 behavior).
    Nested: only if @*.tool decorated (avoids including private helpers).
    """
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node
        # Check descendants at any depth for decorated nested functions.
        for inner in ast.walk(node):
            if inner is node:
                continue
            if isinstance(inner, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_tool_decorated(
                inner
            ):
                yield inner


def extract_docstring_at_line(path: str | Path, line: int) -> str | None:
    """Find docstring of function definition starting at exact line number.

    Used to re-extract docstring text for Layer-2 AI review (needed because
    Semgrep only reports line number, not the text itself).
    """
    source = Path(path).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    # Search all functions at any depth (no decorator filter; Tool Poisoning rule has none).
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno == line:
            return ast.get_docstring(node)
    return None


def _registered_tool_name(node: FunctionNode) -> str | None:
    """Name a @*.tool-decorated function is registered under, else None.

    An explicit name (@mcp.tool("x") or @mcp.tool(name="x")) wins over the function name.
    """
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if not (isinstance(target, ast.Attribute) and target.attr == "tool"):
            continue
        if isinstance(decorator, ast.Call):
            explicit = decorator.args[:1] + [
                keyword.value for keyword in decorator.keywords if keyword.arg == "name"
            ]
            for value in explicit:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    return value.value
        return node.name
    return None


def extract_registered_tool_names(path: str | Path) -> set[str]:
    """Names of all functions registered via @*.tool in the file (any depth). Parse only."""
    source = Path(path).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name = _registered_tool_name(node)
            if name is not None:
                names.add(name)
    return names


def _collect_string_parts(node: ast.AST) -> list[str]:
    """Collect all string constants below node in source order (f-string literal parts included)."""
    if isinstance(node, ast.Constant):
        return [node.value] if isinstance(node.value, str) else []
    parts: list[str] = []
    for child in ast.iter_child_nodes(node):
        parts.extend(_collect_string_parts(child))
    return parts


def extract_return_text_at_line(path: str | Path, line: int) -> str | None:
    """Find the string text of the `return` statement starting at exact line number.

    Used to re-extract handler output text for Layer-2 AI review (P11-3): Semgrep only
    reports the line of the `return`. Placeholders of f-strings and non-string parts are
    dropped; returns None if there is no such return or it contains no string text.
    """
    source = Path(path).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Return) and node.lineno == line and node.value is not None:
            return "".join(_collect_string_parts(node.value)) or None
    return None


def extract_handler_signature_at_line(path: str | Path, line: int) -> dict | None:
    """Find name and docstring of the function that contains the given line.

    Used by the Capability Mismatch check (P11-1): Semgrep reports the line of the
    risky call itself (not the def line), so this looks for the innermost enclosing
    function definition instead of an exact def-line match.
    """
    source = Path(path).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))

    enclosing = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.lineno <= line <= (node.end_lineno or node.lineno):
            if enclosing is None or node.lineno > enclosing.lineno:
                enclosing = node

    if enclosing is None:
        return None
    return {"name": enclosing.name, "docstring": ast.get_docstring(enclosing)}


def extract_tool_schemas(path: str | Path) -> list[dict]:
    """Extract all relevant functions from file: {name, parameters, docstring, body_hash}.

    Parse only, never execute. Includes top-level functions and nested
    functions with @*.tool decorator.
    """
    source = Path(path).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))

    schemas = []
    for node in _iter_relevant_functions(tree):
        docstring = ast.get_docstring(node)
        schemas.append(
            {
                "name": node.name,
                "parameters": _extract_parameters(node.args),
                "docstring": docstring,
                "body_hash": _body_hash(node, docstring),
            }
        )
    return schemas
