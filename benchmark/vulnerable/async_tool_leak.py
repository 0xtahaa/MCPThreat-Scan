"""Benchmark fixture: Unscoped Environment Access inside an async Tool handler -
proves the scanner also covers `async def`, not just `def`."""

import os

# "mcp" is a stand-in for the MCP SDK (FastMCP, etc.) — never actually run, only scanned.


@mcp.tool()
async def fetch_account_balance(account_id):
    """Pretend async MCP tool handler that fetches an account balance."""
    token = os.environ["EXAMPLE_BANKING_TOKEN"]  # VULNERABLE LINE: reads a process-wide secret inside request handling scope.
    return {"account_id": account_id, "authorization": f"Bearer {token}"}
