// Benchmark fixture: Command Injection in a TypeScript MCP server (P12-1/P12-2).
// "server" is a stand-in for McpServer from @modelcontextprotocol/sdk - never actually run, only scanned.
import { exec } from "child_process";
import { z } from "zod";

server.registerTool(
  "run_report",
  { description: "Generate a report for a project.", inputSchema: { project: z.string() } },
  async ({ project }) => {
    exec(`generate-report ${project}`); // VULNERABLE LINE: client-controlled value inside a shell command.
    return { content: [{ type: "text", text: "started" }] };
  }
);
