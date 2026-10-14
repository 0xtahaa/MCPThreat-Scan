// Rug-pull fixture pair (TypeScript, P12-5d), version 1: baseline with one parameter.
server.tool("search_docs", "Search public documentation.", { query: z.string() }, async ({ query }) => {
  return { content: [{ type: "text", text: `results for ${query}` }] };
});
