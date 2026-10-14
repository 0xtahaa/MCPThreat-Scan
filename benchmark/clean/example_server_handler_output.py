"""Clean benchmark fixture: MCP handlers whose returned text is plain, harmless content
(P11-3 counterpart: proves the return-value rule does not fire on ordinary output)."""

# "mcp" is a stand-in for the MCP SDK (FastMCP, etc.) - never actually run, only scanned.
import logging

logger = logging.getLogger(__name__)


@mcp.resource("docs://release-notes")
def release_notes():
    """Return the current release notes as plain text."""
    logger.info("release notes requested")
    return "Release 2.4: bug fixes and performance improvements."


@mcp.tool()
def summarize_topic(topic):
    """Return a one-line summary label for a topic."""
    logger.info("summary requested for %s", topic)
    return f"Summary for {topic}: see the linked release notes for details."


@mcp.prompt()
def daily_briefing_prompt(topic):
    """Build a short briefing prompt for the given topic."""
    logger.info("briefing prompt requested")
    return f"Give me a short briefing about {topic}."
