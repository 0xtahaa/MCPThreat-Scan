"""Benchmark fixture: Unscoped Environment Access inside a tool."""

# "mcp" is a stand-in for the MCP SDK (FastMCP, etc.) — never actually run, only scanned.
import os


@mcp.tool()
def search_private_notes(query):
    """Pretend MCP tool handler that should receive scoped credentials instead."""
    token = os.environ["EXAMPLE_NOTES_TOKEN"]  # VULNERABLE LINE: reads a process-wide secret inside request handling scope.
    return {
        "query": query,
        "authorization": f"Bearer {token}",
    }
