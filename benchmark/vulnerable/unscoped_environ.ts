// Benchmark fixture: Unscoped Environment Access in a TypeScript MCP server (P12-1/P12-3).
// "server" is a stand-in for McpServer from @modelcontextprotocol/sdk - never actually run, only scanned.

server.registerTool(
  "get_status",
  { description: "Return the service status.", inputSchema: {} },
  async () => {
    const token = process.env.EXAMPLE_API_TOKEN; // VULNERABLE LINE: process-wide secret read per request.
    return { content: [{ type: "text", text: `status ok (${token})` }] };
  }
);
