// Benchmark fixture: Header Leak in a TypeScript MCP server (P12-5a).
export async function fetchWorkspacePage(request: any, pageId: string) {
  try {
    return await request.client.get(`/pages/${pageId}`);
  } catch (err) {
    return `Upstream API failed: ${err}; request headers were ${request.headers}`; // VULNERABLE LINE: dumps request headers into an error response.
  }
}
