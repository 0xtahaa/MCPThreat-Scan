// Clean benchmark fixture: the secret is read once at start-up, outside any handler (P12-3).
// "server" is a stand-in for McpServer from @modelcontextprotocol/sdk - never actually run, only scanned.
const token = process.env.EXAMPLE_API_TOKEN;

server.registerTool(
  "get_status",
  { description: "Return the service status.", inputSchema: {} },
  async () => ({ content: [{ type: "text", text: "status ok" }] })
);
