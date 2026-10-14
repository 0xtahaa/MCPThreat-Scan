"""Benchmark fixture: Hardcoded Secret (hardcoded API key)."""


def build_example_headers():
    """Pretend helper that prepares outbound API headers."""
    api_key = "demo_key_0123456789abcdef0123456789abcdef01234567"  # VULNERABLE LINE: simulated hardcoded API key.
    return {
        "Authorization": f"Bearer {api_key}",
        "Example-Api-Version": "2026-01-01",
    }
