"""Reputation/whitelist mechanism: skip Layer-2 AI review for unchanged servers.

Stores SHA-256 fingerprint of reviewed file content. Any byte-level change
invalidates the trust and forces fresh review.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

# Persistent across projects, not reset on re-clone.
DEFAULT_STORE_PATH = Path.home() / ".mcp_scanner" / "reputation.json"


def compute_version_hash(path: str | Path) -> str:
    """Compute SHA-256 fingerprint of file's raw bytes (never executed)."""
    raw_bytes = Path(path).read_bytes()
    return hashlib.sha256(raw_bytes).hexdigest()


def _load_store(store_path: str | Path) -> dict:
    """Load reputation store, return empty dict if not yet created."""
    path = Path(store_path)
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _save_store(store_path: str | Path, data: dict) -> None:
    """Write reputation store to disk, creating parent directory if needed."""
    path = Path(store_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def mark_reviewed(
    name: str,
    path: str | Path,
    *,
    store_path: str | Path = DEFAULT_STORE_PATH,
) -> str:
    """Record that server `name` has been reviewed at its current fingerprint."""
    version_hash = compute_version_hash(path)
    store = _load_store(store_path)
    store[name] = {
        "version_hash": version_hash,
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_store(store_path, store)
    return version_hash


def is_trusted(
    name: str,
    path: str | Path,
    *,
    store_path: str | Path = DEFAULT_STORE_PATH,
) -> bool:
    """Check if server `name`'s file still matches its reviewed fingerprint."""
    store = _load_store(store_path)
    entry = store.get(name)
    if entry is None:
        return False
    current_hash = compute_version_hash(path)
    return current_hash == entry["version_hash"]


def list_reviewed(store_path: str | Path | None = None) -> dict[str, dict]:
    """Return all reviewed servers as {name: {"version_hash", "reviewed_at"}}; empty if no store yet.

    store_path=None resolves DEFAULT_STORE_PATH at call time."""
    return _load_store(DEFAULT_STORE_PATH if store_path is None else store_path)


def revoke_review(name: str, store_path: str | Path | None = None) -> None:
    """Remove the trust entry for `name` (an unknown name leaves the entries unchanged) and save the store."""
    path = DEFAULT_STORE_PATH if store_path is None else store_path
    store = _load_store(path)
    store.pop(name, None)
    _save_store(path, store)
