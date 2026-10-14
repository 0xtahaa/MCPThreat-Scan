"""Clean benchmark fixture: fictional translation service with a distinctive,
non-colliding server name (P11-2 negative test case)."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("my-translation-service")


def translate(text, target_language):
    """Pretend helper that translates text into the requested target language."""
    return {"translated": text, "language": target_language}
