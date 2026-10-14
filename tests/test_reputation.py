"""Tests for P3-2: reputation/trust storage and version-change detection."""

from mcpthreat_scan.policy.reputation import compute_version_hash, is_trusted, mark_reviewed

RUGPULL_DIR = "benchmark/rugpull"
V1_PATH = f"{RUGPULL_DIR}/example_email_bcc_v1.py"
V2_PATH = f"{RUGPULL_DIR}/example_email_bcc_v2.py"


def test_unknown_server_is_not_trusted(tmp_path):
    store_path = tmp_path / "reputation.json"

    assert is_trusted("brand_new_server", V1_PATH, store_path=store_path) is False


def test_reviewed_server_with_identical_code_is_trusted(tmp_path):
    store_path = tmp_path / "reputation.json"

    mark_reviewed("email_relay", V1_PATH, store_path=store_path)

    assert is_trusted("email_relay", V1_PATH, store_path=store_path) is True


def test_reviewed_server_stops_being_trusted_after_code_changes(tmp_path):
    store_path = tmp_path / "reputation.json"

    mark_reviewed("email_relay", V1_PATH, store_path=store_path)

    assert is_trusted("email_relay", V2_PATH, store_path=store_path) is False


def test_mark_reviewed_returns_the_hash_it_stored(tmp_path):
    store_path = tmp_path / "reputation.json"

    returned_hash = mark_reviewed("email_relay", V1_PATH, store_path=store_path)

    assert returned_hash == compute_version_hash(V1_PATH)
    assert len(returned_hash) == 64


def test_store_persists_across_separate_calls(tmp_path):
    store_path = tmp_path / "reputation.json"

    mark_reviewed("weather_service", V1_PATH, store_path=store_path)
    mark_reviewed("notes_service", V2_PATH, store_path=store_path)

    assert is_trusted("weather_service", V1_PATH, store_path=store_path) is True
    assert is_trusted("notes_service", V2_PATH, store_path=store_path) is True
    assert is_trusted("weather_service", V2_PATH, store_path=store_path) is False
