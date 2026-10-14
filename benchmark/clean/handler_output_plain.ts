// Clean benchmark fixture: plain descriptions and plain returned text - no signal words (P12-5a).
// "server" is a stand-in for McpServer from @modelcontextprotocol/sdk - never actually run, only scanned.

server.registerTool(
  "search_docs",
  { description: "Search public documentation.", inputSchema: {} },
  async () => {
    return { content: [{ type: "text", text: "Found 3 results." }] };
  }
);

server.tool("get_version", "Return the server version.", {}, async () => ({
  content: [{ type: "text", text: "Release 2.4: bug fixes and performance improvements." }],
}));
