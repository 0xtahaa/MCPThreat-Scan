"""Benchmark fixture: clean Resource and Prompt handlers - done correctly, should not
trigger unscoped-environ or missing-audit."""

import logging

# "mcp" is a stand-in for the MCP SDK (FastMCP, etc.) — never actually run, only scanned.
SUPPORT_CONTACT = "support@example.invalid"  # loaded once at module level, not per-call.


@mcp.resource("help://contact")
def support_contact_info():
    """Return the static support contact address - no secret, no per-call env access."""
    logging.info("support_contact_info requested")
    return SUPPORT_CONTACT


@mcp.prompt()
def weekly_digest_prompt(topic):
    """Build a weekly digest prompt for the given topic, with audit logging."""
    logging.info("weekly_digest_prompt called with topic=%s", topic)
    return f"Summarize the week's updates about {topic}."
