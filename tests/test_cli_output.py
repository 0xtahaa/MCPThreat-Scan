"""Renderer choice and stdout behaviour of the CLI (AR-131).

The core API is replaced by a fixed finished report, so exactly the wiring is tested:
which renderer runs for which --format, what reaches stdout/stderr, and that both start paths agree."""

import json

import pytest

import mcpthreat_scan.cli.main as target
from mcpthreat_scan.reporting.json import render_json
from mcpthreat_scan.reporting.sarif import render_sarif
from mcpthreat_scan.reporting.text import render_text

REPORT = {
    "target": "srv",
    "findings": [
        {"category": "Header Leak", "file": "a.py", "line": 9, "severity": "ERROR", "message": "Café – ñçü \U0001F512"},
        {"category": "Supply Chain", "file": "requirements.txt", "line": None, "severity": "WARNING", "message": "p"},
    ],
    "summary": {
        "categories_checked": 9,
        "categories_without_finding": 7,
        "categories_with_finding": ["Header Leak", "Supply Chain"],
    },
}
RENDERERS = {"text": render_text, "json": render_json, "sarif": render_sarif}


@pytest.fixture
def cli_main():
    return target.main


@pytest.fixture
def fixed_core(monkeypatch):
    monkeypatch.setattr(target, "run_scan", lambda *a, **k: REPORT)
    monkeypatch.setattr(target, "run_diff", lambda *a, **k: REPORT)


@pytest.fixture
def two_files(tmp_path):
    before, after = tmp_path / "a.py", tmp_path / "b.py"
    before.write_text("x", encoding="utf-8")
    after.write_text("y", encoding="utf-8")
    return str(before), str(after)


@pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
def test_scan_stdout_is_exactly_the_chosen_renderer_output_plus_newline(cli_main, fixed_core, tmp_path, capsys, fmt):
    assert cli_main(["scan", str(tmp_path), "--format", fmt]) == 0

    captured = capsys.readouterr()
    assert captured.out == RENDERERS[fmt](REPORT) + "\n"
    assert captured.err == ""


@pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
def test_diff_stdout_is_exactly_the_chosen_renderer_output_plus_newline(cli_main, fixed_core, two_files, capsys, fmt):
    assert cli_main(["diff", *two_files, "--format", fmt]) == 0

    captured = capsys.readouterr()
    assert captured.out == RENDERERS[fmt](REPORT) + "\n"
    assert captured.err == ""


def test_default_format_is_text_for_both_commands(cli_main, fixed_core, tmp_path, two_files, capsys):
    cli_main(["scan", str(tmp_path)])
    scan_out = capsys.readouterr().out
    cli_main(["diff", *two_files])
    diff_out = capsys.readouterr().out

    assert scan_out == diff_out == render_text(REPORT) + "\n"


@pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
def test_only_the_selected_renderer_is_called(cli_main, fixed_core, tmp_path, monkeypatch, capsys, fmt):
    calls = []
    for name in ("text", "json", "sarif"):
        monkeypatch.setattr(target, f"render_{name}", lambda report, name=name: calls.append(name) or name)

    cli_main(["scan", str(tmp_path), "--format", fmt])

    assert calls == [fmt]
    assert capsys.readouterr().out == fmt + "\n"


def test_json_and_sarif_output_are_parseable_and_keep_unicode(cli_main, fixed_core, tmp_path, capsys):
    cli_main(["scan", str(tmp_path), "--format", "json"])
    parsed = json.loads(capsys.readouterr().out)
    cli_main(["scan", str(tmp_path), "--format", "sarif"])
    sarif = json.loads(capsys.readouterr().out)

    assert parsed == REPORT
    assert sarif["runs"][0]["results"][0]["message"]["text"] == "Café – ñçü \U0001F512"
