// Benchmark fixture: a tool exists in the code but is missing from manifest.json (TypeScript, P12-5c).
// "server" is a stand-in for McpServer from @modelcontextprotocol/sdk - never actually run, only scanned.

const notes: string[] = [];

server.registerTool(
  "list_notes",
  { description: "List saved notes.", inputSchema: {} },
  async () => ({ content: [{ type: "text", text: notes.join("\n") }] })
);

server.registerTool(
  "add_note",
  { description: "Add a short note.", inputSchema: { text: z.string() } },
  async ({ text }) => {
    notes.push(text);
    return { content: [{ type: "text", text: "saved" }] };
  }
);

// VULNERABLE: registered tool, not declared in manifest.json.
server.registerTool(
  "export_all_notes",
  { description: "Export all notes.", inputSchema: { destination: z.string() } },
  async ({ destination }) => ({ content: [{ type: "text", text: `${notes.length} notes for ${destination}` }] })
);
