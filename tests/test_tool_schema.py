"""Tests for P4-1: AST-based tool schema extraction (parameters, docstrings, body hashing)."""

from mcpthreat_scan.diff.tool_schema import extract_tool_schemas

RUGPULL_DIR = "benchmark/rugpull"


def test_extract_search_catalog_v1():
    schemas = extract_tool_schemas(f"{RUGPULL_DIR}/example_search_schema_v1.py")

    assert len(schemas) == 1
    schema = schemas[0]
    assert schema["name"] == "search_catalog"
    assert schema["parameters"] == [
        {"name": "query", "kind": "positional", "default": None},
        {"name": "limit", "kind": "positional", "default": "10"},
    ]
    assert schema["docstring"] == "Search public catalog entries by query text."
    assert len(schema["body_hash"]) == 64


def test_extract_search_catalog_v2_has_new_parameter():
    schemas = extract_tool_schemas(f"{RUGPULL_DIR}/example_search_schema_v2.py")

    assert len(schemas) == 1
    schema = schemas[0]
    assert schema["name"] == "search_catalog"
    assert schema["parameters"] == [
        {"name": "query", "kind": "positional", "default": None},
        {"name": "include_private", "kind": "positional", "default": "False"},
        {"name": "limit", "kind": "positional", "default": "10"},
    ]
    assert schema["docstring"] == (
        "Search public catalog entries. Set include_private=True to include "
        "restricted drafts."
    )


def test_extract_send_project_update_same_signature_across_versions():
    v1 = extract_tool_schemas(f"{RUGPULL_DIR}/example_email_bcc_v1.py")[0]
    v2 = extract_tool_schemas(f"{RUGPULL_DIR}/example_email_bcc_v2.py")[0]

    assert v1["name"] == v2["name"] == "send_project_update"
    assert v1["parameters"] == v2["parameters"]
    assert v1["docstring"] == v2["docstring"]


def test_body_hash_differs_when_implementation_changes():
    v1 = extract_tool_schemas(f"{RUGPULL_DIR}/example_email_bcc_v1.py")[0]
    v2 = extract_tool_schemas(f"{RUGPULL_DIR}/example_email_bcc_v2.py")[0]

    assert v1["body_hash"] != v2["body_hash"]


def test_body_hash_stable_when_implementation_unchanged():
    first = extract_tool_schemas(f"{RUGPULL_DIR}/example_search_schema_v1.py")[0]
    second = extract_tool_schemas(f"{RUGPULL_DIR}/example_search_schema_v1.py")[0]

    assert first["body_hash"] == second["body_hash"]


def test_extract_finds_nested_tool_decorated_function(tmp_path):
    source_file = tmp_path / "server.py"
    source_file.write_text(
        "def register_tools(mcp):\n"
        "    @mcp.tool()\n"
        "    async def authorize_connection(token):\n"
        '        """Authorize an external connection."""\n'
        "        return token\n",
        encoding="utf-8",
    )

    schemas = extract_tool_schemas(source_file)
    names = {schema["name"] for schema in schemas}

    assert "register_tools" in names
    assert "authorize_connection" in names
    nested = next(s for s in schemas if s["name"] == "authorize_connection")
    assert nested["parameters"] == [{"name": "token", "kind": "positional", "default": None}]
    assert nested["docstring"] == "Authorize an external connection."


def test_extract_ignores_nested_function_without_tool_decorator(tmp_path):
    source_file = tmp_path / "server.py"
    source_file.write_text(
        "def register_tools(mcp):\n"
        "    def _internal_helper(x):\n"
        "        return x * 2\n",
        encoding="utf-8",
    )

    schemas = extract_tool_schemas(source_file)
    names = {schema["name"] for schema in schemas}

    assert "register_tools" in names
    assert "_internal_helper" not in names


def test_extract_still_includes_undecorated_top_level_function(tmp_path):
    source_file = tmp_path / "server.py"
    source_file.write_text(
        "def plain_function(x):\n"
        "    return x\n",
        encoding="utf-8",
    )

    schemas = extract_tool_schemas(source_file)

    assert [schema["name"] for schema in schemas] == ["plain_function"]


def test_extract_finds_tool_decorated_method_inside_class(tmp_path):
    source_file = tmp_path / "server.py"
    source_file.write_text(
        "class NotesServer:\n"
        "    @mcp.tool()\n"
        "    def get_note(self, note_id):\n"
        '        """Fetch a single note by id."""\n'
        "        return {\"note_id\": note_id}\n",
        encoding="utf-8",
    )

    schemas = extract_tool_schemas(source_file)
    names = {schema["name"] for schema in schemas}

    assert "get_note" in names
    method = next(s for s in schemas if s["name"] == "get_note")
    assert method["docstring"] == "Fetch a single note by id."
    # "self" is also captured as a parameter - a cosmetic quirk, not a bug.
    assert [p["name"] for p in method["parameters"]] == ["self", "note_id"]


# --- P11-3: return text of a handler for the layer-2 review --------------------------------------


def test_extract_return_text_reads_plain_string(tmp_path):
    from mcpthreat_scan.diff.tool_schema import extract_return_text_at_line

    path = tmp_path / "h.py"
    path.write_text('def f():\n    return "hello <system>x</system>"\n', encoding="utf-8")

    assert extract_return_text_at_line(path, 2) == "hello <system>x</system>"


def test_extract_return_text_keeps_literal_parts_of_fstring_and_concatenation(tmp_path):
    from mcpthreat_scan.diff.tool_schema import extract_return_text_at_line

    path = tmp_path / "h.py"
    path.write_text(
        'def f(x):\n    return f"a {x} b"\n\ndef g(x):\n    return "c " + x + " d"\n',
        encoding="utf-8",
    )

    assert extract_return_text_at_line(path, 2) == "a  b"
    assert extract_return_text_at_line(path, 5) == "c  d"


def test_extract_return_text_returns_none_without_matching_string_return(tmp_path):
    from mcpthreat_scan.diff.tool_schema import extract_return_text_at_line

    path = tmp_path / "h.py"
    path.write_text("def f(x):\n    y = 'a'\n    return x\n", encoding="utf-8")

    assert extract_return_text_at_line(path, 2) is None  # assignment, not a return
    assert extract_return_text_at_line(path, 3) is None  # return without string text
    assert extract_return_text_at_line(path, 99) is None
