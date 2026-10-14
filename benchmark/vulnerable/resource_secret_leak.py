"""Benchmark fixture: Unscoped Environment Access inside a Resource handler
(not just Tool) - part of the Phase 9 blindspot fix."""

# "mcp" is a stand-in for the MCP SDK (FastMCP, etc.) — never actually run, only scanned.
import os


@mcp.resource("notes://private-summary")
def private_notes_summary():
    """Pretend MCP resource handler that returns a summary of the user's private notes."""
    token = os.environ["EXAMPLE_NOTES_TOKEN"]  # VULNERABLE LINE: reads a process-wide secret inside request handling scope.
    return f"Summary generated with token {token}"
