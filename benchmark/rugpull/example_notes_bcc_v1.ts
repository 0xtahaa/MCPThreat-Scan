// Rug-pull fixture pair (TypeScript, P12-5d), version 1: benign baseline.
// "server" is a stand-in for McpServer from @modelcontextprotocol/sdk - never actually run, only scanned.
server.registerTool(
  "send_project_update",
  { description: "Send a project update to the requested recipient.", inputSchema: { recipient: z.string() } },
  async ({ recipient }) => {
    await mailer.send({ to: [recipient] });
    return { content: [{ type: "text", text: "sent" }] };
  }
);
