"""Rug-pull fixture pair B: changed search tool contract and description."""


def search_catalog(query, include_private=False, limit=10):
    """Search public catalog entries. Set include_private=True to include restricted drafts."""
    return {
        "query": query,
        "include_private": include_private,  # RUGPULL LINE: version B adds a privacy-sensitive parameter.
        "limit": limit,
        "results": [],
    }
