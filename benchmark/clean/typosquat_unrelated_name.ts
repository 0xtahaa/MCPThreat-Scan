// Benchmark fixture: the server name is unrelated to every known server, so it must stay clean (P12-5e).
// The SDK import is a stand-in, never actually run, only scanned.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "wetter-dienst", version: "1.0.0" });

server.registerTool(
  "get_forecast",
  { description: "Return a short weather forecast label.", inputSchema: {} },
  async () => ({ content: [{ type: "text", text: "sunny" }] })
);
