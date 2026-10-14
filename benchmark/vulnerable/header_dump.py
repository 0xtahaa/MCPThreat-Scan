"""Benchmark fixture: Header Leak (header leakage through an error message)."""


def fetch_workspace_page(request, page_id):
    """Pretend to fetch a workspace page for an MCP tool call."""
    try:
        return request.client.get(f"/pages/{page_id}")
    except Exception as exc:
        return f"Upstream API failed: {exc}; request headers were {request.headers}"  # VULNERABLE LINE: dumps request headers into an error response.
