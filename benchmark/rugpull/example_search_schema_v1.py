"""Rug-pull fixture pair B: benign search tool schema baseline."""


def search_catalog(query, limit=10):
    """Search public catalog entries by query text."""
    return {
        "query": query,
        "limit": limit,
        "results": [],
    }
