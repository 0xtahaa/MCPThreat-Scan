"""Reporting processes finished results only (AR-120).

While the three renderers run, every file, process and network entry point raises. The reports
name files that do not exist; a renderer that tried to open, scan or resolve them would fail."""

import builtins
import pathlib
import socket
import subprocess

import pytest

from mcpthreat_scan.reporting.json import render_json
from mcpthreat_scan.reporting.sarif import render_sarif
from mcpthreat_scan.reporting.text import render_text

REPORT = {
    "target": "C:\\does\\not\\exist",
    "findings": [
        {"category": "Header Leak", "file": "no/such/file.py", "line": 3, "severity": "ERROR", "message": "m"},
        {"category": "Supply Chain", "file": "no/such/requirements.txt", "line": None, "severity": "ERROR", "message": "p"},
    ],
    "summary": {"categories_checked": 9, "categories_without_finding": 7, "categories_with_finding": ["Header Leak", "Supply Chain"]},
}


def _forbidden(*args, **kwargs):
    raise AssertionError("reporting must not touch files, processes or the network")


@pytest.fixture
def no_io(monkeypatch):
    monkeypatch.setattr(builtins, "open", _forbidden)
    for name in ("read_text", "read_bytes", "write_text", "write_bytes", "exists", "is_file", "is_dir",
                 "iterdir", "glob", "rglob", "mkdir", "unlink", "resolve", "stat", "open"):
        monkeypatch.setattr(pathlib.Path, name, _forbidden)
    monkeypatch.setattr(subprocess, "run", _forbidden)
    monkeypatch.setattr(subprocess, "Popen", _forbidden)
    monkeypatch.setattr(socket, "socket", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)


@pytest.mark.parametrize("render", [render_text, render_json, render_sarif])
def test_renderer_works_on_a_finished_report_without_any_io(no_io, render):
    output = render(REPORT)

    assert isinstance(output, str) and output


def test_the_no_io_fixture_really_blocks_file_access(no_io):
    with pytest.raises(AssertionError):
        pathlib.Path("anything").read_text()
    with pytest.raises(AssertionError):
        open("anything")
