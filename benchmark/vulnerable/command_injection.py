"""Benchmark fixture: Command Injection through unchecked input."""

import os


def convert_document(filename):
    """Pretend MCP tool handler that converts a user-selected document."""
    command = f"pandoc uploads/{filename} -o output.pdf"
    return os.system(command)  # VULNERABLE LINE: passes unchecked user-controlled input to a shell command.
