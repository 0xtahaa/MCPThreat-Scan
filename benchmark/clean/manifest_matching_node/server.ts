// Benchmark fixture: every registered tool is declared in manifest.json (TypeScript, P12-5c).
// "server" is a stand-in for McpServer from @modelcontextprotocol/sdk - never actually run, only scanned.

const notes: string[] = [];

server.registerTool(
  "list_notes",
  { description: "List saved notes.", inputSchema: {} },
  async () => ({ content: [{ type: "text", text: notes.join("\n") }] })
);

// Legacy call form: server.tool(name, description, schema, handler).
server.tool("add_note", "Add a short note.", { text: z.string() }, async ({ text }) => {
  notes.push(text);
  return { content: [{ type: "text", text: "saved" }] };
});

server.registerTool(
  "export_all_notes",
  { description: "Export all notes.", inputSchema: { destination: z.string() } },
  async ({ destination }) => ({ content: [{ type: "text", text: `${notes.length} notes for ${destination}` }] })
);
