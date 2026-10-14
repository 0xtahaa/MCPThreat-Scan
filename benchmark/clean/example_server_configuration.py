"""Clean fixture: config loader reading os.environ at startup (not in a tool handler)."""

import os


def load_configuration():
    """Read connection settings once at server start-up - not a tool handler."""
    api_base_url = os.environ.get("EXAMPLE_API_BASE_URL", "https://api.example.invalid")
    max_retries = int(os.environ.get("EXAMPLE_MAX_RETRIES", "3"))
    return {"api_base_url": api_base_url, "max_retries": max_retries}
