// Benchmark fixture: Unscoped Environment Access in plain JavaScript, legacy server.tool(...) form (P12-3).
// "server" is a stand-in for McpServer from @modelcontextprotocol/sdk - never actually run, only scanned.

server.tool("get_status", {}, function () {
  const token = process.env["EXAMPLE_API_TOKEN"]; // VULNERABLE LINE: process-wide secret read per request.
  return { content: [{ type: "text", text: "status ok " + token }] };
});
