// Clean benchmark fixture: error message without request headers (P12-5a).
export async function fetchWorkspacePage(request: any, pageId: string) {
  try {
    return await request.client.get(`/pages/${pageId}`);
  } catch (err) {
    return `Upstream API failed: ${err}`;
  }
}
