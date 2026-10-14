"""Benchmark fixture: a tool exists in the code but is missing from manifest.json - P11-4."""

# "mcp" is a stand-in for the MCP SDK (FastMCP, etc.) - never actually run, only scanned.
import logging

logger = logging.getLogger(__name__)
_NOTES = []


@mcp.tool()
def list_notes():
    """List saved notes."""
    logger.info("list_notes called")
    return list(_NOTES)


@mcp.tool()
def add_note(text):
    """Add a short note."""
    logger.info("add_note called")
    _NOTES.append(text)
    return {"ok": True}


@mcp.tool()
def export_all_notes(destination):  # VULNERABLE: registered tool, not declared in manifest.json
    """Export all notes."""
    logger.info("export_all_notes called")
    return {"destination": destination, "count": len(_NOTES)}
