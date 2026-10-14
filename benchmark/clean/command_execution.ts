// Clean benchmark fixture: same purpose as vulnerable/command_injection.ts, but without a shell (P12-2).
// "server" is a stand-in for McpServer from @modelcontextprotocol/sdk - never actually run, only scanned.
import { execFile } from "child_process";
import { z } from "zod";

server.registerTool(
  "run_report",
  { description: "Generate a report for a project.", inputSchema: { project: z.string() } },
  async ({ project }) => {
    execFile("generate-report", [project]); // argument list, no shell interpretation
    return { content: [{ type: "text", text: "started" }] };
  }
);
