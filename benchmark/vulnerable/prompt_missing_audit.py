"""Benchmark fixture: Missing Audit Logging inside a Prompt handler
(not just Tool) - part of the Phase 9 blindspot fix."""

# "mcp" is a stand-in for the MCP SDK (FastMCP, etc.) — never actually run, only scanned.


@mcp.prompt()
def daily_briefing_prompt(topic):
    """Pretend MCP prompt handler that builds a daily briefing prompt for the given topic."""
    return f"Give me a short briefing about {topic}."  # VULNERABLE LINE: no logging call anywhere in this function.
