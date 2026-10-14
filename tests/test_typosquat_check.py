"""Tests for P11-2: Typosquatting/Shadow-Server heuristic."""

from mcpthreat_scan.analyzers.typosquat import (
    check_typosquat,
    extract_declared_server_name,
    find_typosquat_candidate,
    load_known_servers,
)

VULNERABLE_PATH = "benchmark/vulnerable/typosquat_server_name.py"
CLEAN_PATH = "benchmark/clean/example_server_translation.py"

KNOWN_SERVERS = ["blender-mcp", "github", "slack-mcp-server"]


def test_extract_finds_name_from_positional_fastmcp_call(tmp_path):
    source_file = tmp_path / "server.py"
    source_file.write_text('mcp = FastMCP("wetter-dienst")\n', encoding="utf-8")

    result = extract_declared_server_name(source_file)

    assert result == ("wetter-dienst", 1)


def test_extract_finds_name_from_keyword_argument(tmp_path):
    source_file = tmp_path / "server.py"
    source_file.write_text('mcp = FastMCP(name="wetter-dienst")\n', encoding="utf-8")

    result = extract_declared_server_name(source_file)

    assert result == ("wetter-dienst", 1)


def test_extract_returns_none_without_server_declaration(tmp_path):
    source_file = tmp_path / "server.py"
    source_file.write_text("def helper():\n    return 1\n", encoding="utf-8")

    assert extract_declared_server_name(source_file) is None


def test_find_typosquat_candidate_flags_near_miss():
    candidate = find_typosquat_candidate("blender-msp", KNOWN_SERVERS)

    assert candidate is not None
    assert candidate["matched_name"] == "blender-mcp"
    assert candidate["similarity"] >= 0.7


def test_find_typosquat_candidate_ignores_exact_match():
    assert find_typosquat_candidate("blender-mcp", KNOWN_SERVERS) is None


def test_find_typosquat_candidate_ignores_clearly_different_name():
    assert find_typosquat_candidate("mein-ganz-eigener-notizserver", KNOWN_SERVERS) is None


def test_check_typosquat_flags_the_vulnerable_fixture():
    findings = check_typosquat(VULNERABLE_PATH)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["category"] == "Typosquatting / Shadow-Server"
    assert finding["severity"] == "WARNING"
    assert "blender-mcp" in finding["message"]


def test_check_typosquat_leaves_the_clean_fixture_alone():
    assert check_typosquat(CLEAN_PATH) == []


def test_load_known_servers_contains_real_curated_list():
    servers = load_known_servers()

    assert "blender-mcp" in servers
    assert len(servers) > 400


# --- P12-5e: TypeScript server names --------------------------------------------------------


def test_orchestrator_stage_flags_typosquat_in_a_typescript_file():
    from mcpthreat_scan.core import orchestrator

    findings = orchestrator._run_typosquat_stage(
        orchestrator.Path("benchmark/vulnerable/typosquat_server_name.ts")
    )

    assert [f["category"] for f in findings] == ["Typosquatting / Shadow-Server"]
    assert "blender-mcp" in findings[0]["message"] and findings[0]["line"] == 6


def test_orchestrator_stage_is_silent_for_an_unrelated_typescript_name():
    from mcpthreat_scan.core import orchestrator

    assert orchestrator._run_typosquat_stage(
        orchestrator.Path("benchmark/clean/typosquat_unrelated_name.ts")
    ) == []


def test_orchestrator_stage_scans_ts_files_in_a_folder_but_not_node_modules(tmp_path):
    from mcpthreat_scan.core import orchestrator

    squat = 'new McpServer({ name: "blender-msp", version: "1" });\n'
    (tmp_path / "server.ts").write_text(squat, encoding="utf-8")
    vendored = tmp_path / "node_modules" / "dep"
    vendored.mkdir(parents=True)
    (vendored / "index.js").write_text(squat, encoding="utf-8")

    findings = orchestrator._run_typosquat_stage(tmp_path)

    assert [orchestrator.Path(f["file"]).name for f in findings] == ["server.ts"]


def test_check_declared_name_accepts_a_name_from_any_language():
    from mcpthreat_scan.analyzers.typosquat import check_declared_name

    rows = check_declared_name("x.ts", "blender-msp", 3)

    assert rows[0]["line"] == 3 and rows[0]["file"] == "x.ts"
    assert check_declared_name("x.ts", "blender-mcp", 3) == []  # exact match is not a squat
