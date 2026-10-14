"""Extract tool schemas (name, parameters, description, body hash) from TypeScript/JavaScript files.

Parse only, never execute. This is the TS/JS counterpart of diff/tool_schema.py (which does the
same for Python). The returned dicts use the same keys, so later tasks (manifest check, rug-pull
diff, typosquat) can treat both languages alike. Scanned code is never run.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import tree_sitter_typescript
from tree_sitter import Language, Node, Parser

# The TSX grammar is a superset of TypeScript and also accepts plain JavaScript (.js/.mjs/.cjs),
# so one parser is enough for every file type we scan.
_PARSER = Parser(Language(tree_sitter_typescript.language_tsx()))

# The two ways the MCP SDK registers a tool: legacy server.tool(...) and server.registerTool(...).
_TOOL_METHODS = {"tool", "registerTool"}

# File extensions this module can read (the TSX grammar parses all of them).
TS_JS_SUFFIXES = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}

# Build output is not source: skip minified bundles and anything above this size (the same
# 1 MB limit Semgrep applies by default), so one huge file cannot stall a scan.
MAX_TS_FILE_BYTES = 1_000_000


def ts_skip_reason(path: str | Path) -> str | None:
    """Why a TS/JS file is not parsed ("minified file", "larger than 1000 KB"), else None."""
    path = Path(path)
    if path.name.lower().endswith((".min.js", ".min.mjs", ".min.cjs")):
        return "minified file"
    if path.stat().st_size > MAX_TS_FILE_BYTES:
        return f"larger than {MAX_TS_FILE_BYTES // 1000} KB"
    return None


# SDK classes whose constructor declares the server name: new McpServer({ name }) / new Server({ name }).
_SERVER_CONSTRUCTORS = {"McpServer", "Server"}

# Node types that can be a tool handler function (arrow function, function expression, ...).
_HANDLER_TYPES = {"arrow_function", "function_expression", "function", "generator_function"}


def _text(node: Node) -> str:
    """Return the source text of a node as a normal string."""
    # tree-sitter gives bytes; errors="replace" keeps odd bytes from crashing the scan.
    return node.text.decode("utf-8", errors="replace")


def _string_value(node: Node | None, consts: dict[str, str] | None = None) -> str | None:
    """Return the text of a plain string literal, or None if it is anything else.

    With `consts` (from _collect_constants) a name of a file-level constant and a "+" join of
    readable parts are resolved too. Without it only literals count - used for property keys,
    where an identifier is a property name and must never be replaced by a constant's value.
    """
    if node is None:
        return None
    if node.type == "string":
        # Cut off the first and last character, which are the two quote marks.
        return _text(node)[1:-1]
    if node.type == "template_string" and not any(
        child.type == "template_substitution" for child in node.children
    ):
        # A backtick string is only "plain" if it has no ${...} parts inside.
        return _text(node)[1:-1]
    if consts is not None:
        if node.type == "identifier":
            return consts.get(_text(node))
        if node.type == "binary_expression":
            operator = node.child_by_field_name("operator")
            if operator is not None and _text(operator) == "+":
                left = _string_value(node.child_by_field_name("left"), consts)
                right = _string_value(node.child_by_field_name("right"), consts)
                if left is not None and right is not None:
                    return left + right
    # A function call, a template with ${...}, an unknown variable ... is not statically readable.
    return None


def _binding_names(node: Node) -> list[str]:
    """Every name a declaration or parameter list binds (also inside destructuring patterns)."""
    names = []
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type in ("identifier", "shorthand_property_identifier_pattern"):
            names.append(_text(current))
        stack.extend(current.children)
    return names


def _collect_constants(root: Node) -> dict[str, str]:
    """File-level `const NAME = "text"` values that are safe to substitute for NAME.

    A name counts only if it is bound exactly once in the whole file (as that const). A second
    declaration, a parameter or a destructuring with the same name could shadow it, and then the
    value at the use site is unknown - so such names are left unresolved rather than guessed.
    """
    literals: dict[str, str] = {}
    bound_count: dict[str, int] = {}
    stack = [root]
    while stack:
        node = stack.pop()
        bound_here: list[str] = []
        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                bound_here = _binding_names(name_node)
                parent = node.parent
                is_const = parent is not None and parent.type == "lexical_declaration" and any(
                    child.type == "const" for child in parent.children
                )
                # Literals and "+" joins of literals; {} means "no other constant is known yet".
                value = _string_value(node.child_by_field_name("value"), {})
                if is_const and name_node.type == "identifier" and value is not None:
                    literals[_text(name_node)] = value
        elif node.type == "formal_parameters":
            bound_here = _binding_names(node)
        elif node.type == "arrow_function":
            parameter = node.child_by_field_name("parameter")  # x => ... without parentheses
            if parameter is not None:
                bound_here = _binding_names(parameter)
        for name in bound_here:
            bound_count[name] = bound_count.get(name, 0) + 1
        stack.extend(node.children)
    return {name: value for name, value in literals.items() if bound_count.get(name) == 1}


def _property_name(key_node: Node) -> str:
    """Return a property name, whether it was written as name, "name" or 'name'."""
    return _string_value(key_node) or _text(key_node)


def _object_keys(node: Node) -> list[str]:
    """Return the property names of an object literal, e.g. { path: z.string() } -> ["path"]."""
    keys = []
    for child in node.named_children:
        if child.type == "pair":
            # A normal entry "key: value": the name is in the "key" field.
            key_node = child.child_by_field_name("key")
            if key_node is not None:
                keys.append(_property_name(key_node))
        elif child.type == "shorthand_property_identifier":
            # Short form { path } - the identifier itself is the name.
            keys.append(_text(child))
    return keys


def _find_property(obj: Node, name: str) -> Node | None:
    """Return the value node of property `name` in an object literal, or None if it is missing."""
    for child in obj.named_children:
        if child.type != "pair":
            continue
        key_node = child.child_by_field_name("key")
        if key_node is not None and _property_name(key_node) == name:
            return child.child_by_field_name("value")
    return None


def _body_hash(handler: Node | None) -> str | None:
    """SHA-256 fingerprint of the handler's tokens; whitespace and comments do not change it."""
    if handler is None:
        return None
    tokens: list[str] = []

    def collect(node: Node) -> None:
        if node.type == "comment":
            return  # Comments are not behavior, so a changed comment must not change the hash.
        if node.child_count == 0:
            tokens.append(_text(node))  # A leaf node is one token (a word, a symbol, a string).
        for child in node.children:
            collect(child)

    collect(handler)
    # Join with an unusual separator so ["ab", "c"] and ["a", "bc"] cannot give the same hash.
    return hashlib.sha256("\x1f".join(tokens).encode("utf-8")).hexdigest()


def _tool_from_call(call: Node, consts: dict[str, str]) -> dict | None:
    """Turn one server.tool(...) / server.registerTool(...) call into a schema dict, else None."""
    function = call.child_by_field_name("function")
    arguments = call.child_by_field_name("arguments")
    # We only care about calls shaped like  something.method(...).
    if function is None or arguments is None or function.type != "member_expression":
        return None
    method_node = function.child_by_field_name("property")
    if method_node is None or _text(method_node) not in _TOOL_METHODS:
        return None
    method = _text(method_node)

    # Real arguments only; comments between arguments are not arguments.
    args = [arg for arg in arguments.named_children if arg.type != "comment"]
    if not args:
        return None

    description = None
    parameters: list[str] = []
    rest = args[1:]  # Everything after the tool name.
    if method == "registerTool":
        # registerTool(name, { description, inputSchema }, handler)
        if rest and rest[0].type == "object":
            description = _string_value(_find_property(rest[0], "description"), consts)
            schema = _find_property(rest[0], "inputSchema")
            if schema is not None and schema.type == "object":
                parameters = _object_keys(schema)
    else:
        # Legacy form: tool(name, [description], [schema], handler)
        if rest and _string_value(rest[0], consts) is not None:
            description = _string_value(rest[0], consts)
            rest = rest[1:]
        if rest and rest[0].type == "object":
            parameters = _object_keys(rest[0])

    # The handler is the last argument, if it is a function.
    handler = args[-1] if args[-1].type in _HANDLER_TYPES else None
    return {
        # None means "not a plain string", i.e. the name is not statically readable.
        "name": _string_value(args[0], consts),
        "parameters": [{"name": p, "kind": "schema_key", "default": None} for p in parameters],
        # Same key as the Python extractor; here it holds the tool description.
        "docstring": description,
        "body_hash": _body_hash(handler),
        "line": call.start_point[0] + 1,  # tree-sitter counts lines from 0, humans from 1.
    }


def extract_ts_tool_schemas(path: str | Path) -> list[dict]:
    """Extract all tool registrations from a .ts/.js file.

    Returns a list of {name, parameters, docstring, body_hash, line}. Parse only, never execute.
    """
    if ts_skip_reason(path):
        return []  # build output; the orchestrator reports the skip as an INFO row
    # Read raw bytes: tree-sitter works on bytes and a broken file still gives a partial tree.
    tree = _PARSER.parse(Path(path).read_bytes())
    schemas = []
    consts = _collect_constants(tree.root_node)
    stack = [tree.root_node]  # Walk the whole tree without recursion (deep files cannot overflow).
    while stack:
        node = stack.pop()
        if node.type == "call_expression":
            schema = _tool_from_call(node, consts)
            if schema is not None:
                schemas.append(schema)
        # Reversed, so the stack hands the children back in source order.
        stack.extend(reversed(node.children))
    return schemas


def extract_ts_registered_tool_names(path: str | Path) -> set[str]:
    """Names of all tools registered in the file; tools with a non-literal name are left out."""
    return {schema["name"] for schema in extract_ts_tool_schemas(path) if schema["name"] is not None}


def extract_ts_declared_server_name(path: str | Path) -> tuple[str, int] | None:
    """Find the first new McpServer({ name }) / new Server({ name }, ...) and return (name, line).

    Counterpart of typosquat.extract_declared_server_name for Python. Parse only, never execute.
    """
    if ts_skip_reason(path):
        return None
    tree = _PARSER.parse(Path(path).read_bytes())
    consts = _collect_constants(tree.root_node)
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "new_expression":
            constructor = node.child_by_field_name("constructor")
            arguments = node.child_by_field_name("arguments")
            if (
                constructor is not None
                and arguments is not None
                and _text(constructor) in _SERVER_CONSTRUCTORS
            ):
                # Both SDK classes take the server info object { name, version } as first argument.
                args = [arg for arg in arguments.named_children if arg.type != "comment"]
                if args and args[0].type == "object":
                    name = _string_value(_find_property(args[0], "name"), consts)
                    if name is not None:
                        return name, node.start_point[0] + 1
        stack.extend(reversed(node.children))
    return None


# Registration methods the Tool Poisoning rules (tool_poisoning_node.yaml) look at.
_REGISTER_METHODS = {
    "tool", "registerTool", "resource", "registerResource", "prompt", "registerPrompt",
}


def extract_ts_description_at_line(path: str | Path, line: int) -> str | None:
    """Description of the tool/resource/prompt registration call that starts at `line`.

    Counterpart of extract_docstring_at_line (Python): Semgrep only reports the line, and the
    Layer-2 AI review needs the text. Handles the config-object form ({ description }) and the
    legacy positional description string. None if nothing readable is found there.
    """
    if ts_skip_reason(path):
        return None
    tree = _PARSER.parse(Path(path).read_bytes())
    consts = _collect_constants(tree.root_node)
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "call_expression" and node.start_point[0] + 1 == line:
            function = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            method = function.child_by_field_name("property") if function is not None else None
            if (
                function is not None
                and function.type == "member_expression"
                and arguments is not None
                and method is not None
                and _text(method) in _REGISTER_METHODS
            ):
                args = [arg for arg in arguments.named_children if arg.type != "comment"]
                for arg in args[1:]:
                    if arg.type == "object":
                        found = _string_value(_find_property(arg, "description"), consts)
                        if found is not None:
                            return found
                if len(args) > 1:
                    return _string_value(args[1], consts)
        stack.extend(node.children)
    return None


def _collect_string_parts(node: Node) -> list[str]:
    """All string text below node in source order; ${...} placeholders of templates are dropped."""
    if node.type == "string":
        return [_text(node)[1:-1]]
    if node.type == "template_string":
        return [_text(child) for child in node.children if child.type == "string_fragment"]
    parts: list[str] = []
    for child in node.children:
        parts.extend(_collect_string_parts(child))
    return parts


def extract_ts_return_text_at_line(path: str | Path, line: int) -> str | None:
    """String text of the `return` statement that starts at `line` (counterpart of the Python one).

    Used to re-extract handler output text for the Layer-2 AI review. None if there is no such
    return or it contains no string text.
    """
    if ts_skip_reason(path):
        return None
    tree = _PARSER.parse(Path(path).read_bytes())
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "return_statement" and node.start_point[0] + 1 == line:
            return "\n".join(_collect_string_parts(node)) or None
        stack.extend(node.children)
    return None
