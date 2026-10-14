"""Tests for P5-1: Semgrep wrapper (findings normalization and metadata extraction)."""

from mcpthreat_scan.analyzers.semgrep import run_semgrep_rules


def test_finds_known_vulnerable_file_with_correct_metadata():
    """Command Injection fixture must produce one finding with correct category/severity/line."""
    findings = run_semgrep_rules("benchmark/vulnerable/command_injection.py")

    assert len(findings) == 1
    finding = findings[0]
    assert finding["line"] == 9
    assert finding["category"] == "Command Injection"
    assert finding["severity"] == "ERROR"
    assert "command-injection" in finding["rule_id"]


def test_clean_file_produces_no_findings():
    """Clean fixture must produce zero findings."""
    findings = run_semgrep_rules("benchmark/clean/example_server_weather.py")

    assert findings == []


def test_whole_benchmark_matches_known_total_count():
    """Entire benchmark must produce 12 findings (P9-2 reference)."""
    findings = run_semgrep_rules("benchmark/")

    assert len(findings) == 28


def test_output_rule_flags_return_text_in_resource_tool_and_prompt_handlers():
    """P11-3: hidden instruction in a handler's return value is a Tool Poisoning candidate."""
    for name, line in [
        ("resource_output_injection", 14),
        ("tool_output_injection", 14),
        ("prompt_output_injection", 14),
    ]:
        findings = run_semgrep_rules(f"benchmark/vulnerable/{name}.py")

        assert [(f["category"], f["severity"], f["line"]) for f in findings] == [
            ("Tool Poisoning", "WARNING", line)
        ], name
        assert findings[0]["rule_id"].endswith("tool-poisoning-output-candidate"), name


def test_output_rule_stays_silent_on_plain_handler_output():
    findings = run_semgrep_rules("benchmark/clean/example_server_handler_output.py")

    assert findings == []


def test_node_rules_flag_ts_fixtures_with_the_expected_rule_and_line():
    """P12-5a: ported TS/JS rules (secret, header leak, tool poisoning in description and output)."""
    expected = {
        "benchmark/vulnerable/hardcoded_api_key.ts": ("hardcoded-secret-node", 3),
        "benchmark/vulnerable/header_dump.ts": ("header-leak-node", 6),
        "benchmark/vulnerable/tool_description_injection.ts": (
            "tool-poisoning-description-node-candidate", 4),
        "benchmark/vulnerable/tool_output_injection.ts": ("tool-poisoning-output-node-candidate", 8),
    }
    for path, (rule, line) in expected.items():
        findings = run_semgrep_rules(path)

        assert (findings[0]["rule_id"].rsplit(".", 1)[-1], findings[0]["line"]) == (rule, line), path


def test_node_rules_stay_silent_on_clean_ts_fixtures():
    for path in (
        "benchmark/clean/config_constants.ts",
        "benchmark/clean/error_without_headers.ts",
        "benchmark/clean/handler_output_plain.ts",
        "benchmark/clean/command_execution.ts",
        "benchmark/clean/env_at_startup.ts",
    ):
        assert run_semgrep_rules(path) == [], path


def test_node_secret_rule_ignores_interpolated_template_literals(tmp_path):
    source = tmp_path / "headers.ts"
    source.write_text(
        "const headers = { Authorization: `Bearer ${process.env.EXAMPLE_TOKEN}` };\n"
        "const apiKey = `key_${Date.now()}_abcdefghijklmnop`;\n",
        encoding="utf-8",
    )

    assert run_semgrep_rules(source) == []
