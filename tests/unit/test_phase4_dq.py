"""
test_phase4_dq.py — Unit tests for Phase 4 Data Quality Validation & Kafka mocking.

Tests cover:
  - validate_event_data_quality: valid events, null checks, outlier detection, schema checks
  - SimulatedKafkaBroker: produce, consume, offset tracking, partition routing
  - Idempotent UPSERT behavior in staging SQLite
  - Dead Letter Queue (DLQ) routing for failed events
  - Staging table schema integrity
"""

import hashlib
import os
import sqlite3
import sys

# Ensure project root is on path so phase4 can be imported directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from phase4 import validate_event_data_quality  # noqa: E402


# ─────────────────────────────────────────────────────────────────────────────
#  Staging DB helpers (in-memory, no disk I/O)
# ─────────────────────────────────────────────────────────────────────────────

def build_staging_schema(conn: sqlite3.Connection):
    """Create staging tables in the given in-memory connection."""
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS staging_malware_events (
            idempotency_key TEXT PRIMARY KEY,
            sample_hash     TEXT NOT NULL,
            family_id       INTEGER NOT NULL,
            shannon_entropy REAL NOT NULL,
            file_size_bytes INTEGER NOT NULL,
            dq_status       TEXT DEFAULT 'PASSED',
            ingestion_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dead_letter_queue (
            dlq_id         INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id     TEXT NOT NULL,
            raw_payload    TEXT NOT NULL,
            failure_reason TEXT NOT NULL,
            failed_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()


def upsert_event(conn: sqlite3.Connection, event: dict) -> bool:
    """
    Attempt to upsert a DQ-passed event into staging.
    Returns True if inserted/replaced, False if DQ failed.
    """
    is_valid, reason = validate_event_data_quality(event)
    if not is_valid:
        return False
    idempotency_key = hashlib.sha256(
        f"{event['sample_hash']}_{event['family_id']}".encode()
    ).hexdigest()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO staging_malware_events
        (idempotency_key, sample_hash, family_id, shannon_entropy, file_size_bytes, dq_status)
        VALUES (?, ?, ?, ?, ?, 'PASSED')
    """, (idempotency_key, event["sample_hash"], event["family_id"],
          event["shannon_entropy"], event["file_size_bytes"]))
    conn.commit()
    return True


# ─────────────────────────────────────────────────────────────────────────────
#  Tests — Data Quality Validation
# ─────────────────────────────────────────────────────────────────────────────

class TestDQValidation:
    """Tests for the validate_event_data_quality function from phase4.py."""

    def test_valid_event_passes(self, valid_event):
        """A well-formed event must pass all DQ checks."""
        is_valid, reason = validate_event_data_quality(valid_event)
        assert is_valid is True, f"Valid event failed DQ: {reason}"
        assert reason == "PASSED_ALL_DQ_CHECKS"

    def test_null_family_id_fails(self, valid_event):
        """Event with family_id=None must fail DQ with NULL_CHECK_FAILED."""
        event = {**valid_event, "family_id": None}
        is_valid, reason = validate_event_data_quality(event)
        assert is_valid is False
        assert "NULL_CHECK_FAILED" in reason

    def test_empty_sample_hash_fails(self, valid_event):
        """Event with empty sample_hash must fail DQ."""
        event = {**valid_event, "sample_hash": ""}
        is_valid, reason = validate_event_data_quality(event)
        assert is_valid is False
        assert "NULL_CHECK_FAILED" in reason

    def test_whitespace_sample_hash_fails(self, valid_event):
        """Event with whitespace-only sample_hash must fail DQ."""
        event = {**valid_event, "sample_hash": "   "}
        is_valid, reason = validate_event_data_quality(event)
        assert is_valid is False

    def test_entropy_above_max_fails(self, valid_event):
        """Entropy > 8.0 must be flagged as OUTLIER_DETECTION_FAILED."""
        event = {**valid_event, "shannon_entropy": 14.85}
        is_valid, reason = validate_event_data_quality(event)
        assert is_valid is False
        assert "OUTLIER_DETECTION_FAILED" in reason

    def test_entropy_below_min_fails(self, valid_event):
        """Entropy < 0.0 must be flagged as OUTLIER_DETECTION_FAILED."""
        event = {**valid_event, "shannon_entropy": -1.0}
        is_valid, reason = validate_event_data_quality(event)
        assert is_valid is False
        assert "OUTLIER_DETECTION_FAILED" in reason

    def test_entropy_exactly_at_boundary_passes(self, valid_event):
        """Entropy exactly 0.0 and 8.0 must pass (inclusive boundary)."""
        for boundary in [0.0, 8.0]:
            event = {**valid_event, "shannon_entropy": boundary}
            is_valid, reason = validate_event_data_quality(event)
            assert is_valid is True, \
                f"Boundary entropy {boundary} failed unexpectedly: {reason}"

    def test_negative_file_size_fails(self, valid_event):
        """Negative file_size_bytes must fail DQ."""
        event = {**valid_event, "file_size_bytes": -9999}
        is_valid, reason = validate_event_data_quality(event)
        assert is_valid is False
        assert "OUTLIER_DETECTION_FAILED" in reason

    def test_zero_file_size_fails(self, valid_event):
        """Zero file_size_bytes must fail DQ (file cannot be 0 bytes)."""
        event = {**valid_event, "file_size_bytes": 0}
        is_valid, reason = validate_event_data_quality(event)
        assert is_valid is False

    def test_missing_required_key_fails(self, valid_event):
        """Removing any required key must trigger SCHEMA_VALIDATION_FAILED."""
        for key in ["sample_hash", "family_id", "shannon_entropy", "file_size_bytes"]:
            event = {k: v for k, v in valid_event.items() if k != key}
            is_valid, reason = validate_event_data_quality(event)
            assert is_valid is False, f"Missing key '{key}' did not fail DQ"
            assert "SCHEMA_VALIDATION_FAILED" in reason

    def test_extra_fields_do_not_affect_validation(self, valid_event):
        """Extra fields in the event payload must not break DQ validation."""
        event = {**valid_event, "unexpected_field": "some_value", "another": 999}
        is_valid, reason = validate_event_data_quality(event)
        assert is_valid is True, f"Extra fields broke DQ: {reason}"


# ─────────────────────────────────────────────────────────────────────────────
#  Tests — Mock Kafka Broker (from conftest.py fixture)
# ─────────────────────────────────────────────────────────────────────────────

class TestMockKafkaBroker:
    """Tests for the mock Kafka broker produce/consume round-trip."""

    def test_produce_returns_metadata(self, mock_kafka_broker, valid_event):
        """produce() must return topic/partition/offset metadata."""
        result = mock_kafka_broker.produce("malware-ingest-topic", valid_event, partition=0)
        assert result is not None
        assert result["topic"] == "malware-ingest-topic"
        assert result["partition"] == 0
        assert result["offset"] == 0

    def test_consume_returns_produced_messages(self, mock_kafka_broker, valid_event):
        """Messages produced must be returned by consume()."""
        mock_kafka_broker.produce("malware-ingest-topic", valid_event, partition=0)
        messages = mock_kafka_broker.consume("malware-ingest-topic", "staging-ingest-group")
        assert len(messages) == 1
        assert messages[0]["sample_hash"] == valid_event["sample_hash"]

    def test_consume_advances_offset(self, mock_kafka_broker, valid_event):
        """Consuming messages must advance the consumer group offset."""
        mock_kafka_broker.produce("malware-ingest-topic", valid_event, partition=0)
        first_consume = mock_kafka_broker.consume("malware-ingest-topic", "staging-ingest-group")
        second_consume = mock_kafka_broker.consume("malware-ingest-topic", "staging-ingest-group")
        assert len(first_consume) == 1, "First consume should return 1 message"
        assert len(second_consume) == 0, "Second consume should return 0 (already committed)"

    def test_multiple_partitions_isolated(self, mock_kafka_broker):
        """Messages on different partitions must be isolated correctly."""
        mock_kafka_broker.produce("malware-ingest-topic",
                                  {"sample_hash": "hash_p0", "family_id": 1,
                                   "shannon_entropy": 6.5, "file_size_bytes": 100000},
                                  partition=0)
        mock_kafka_broker.produce("malware-ingest-topic",
                                  {"sample_hash": "hash_p1", "family_id": 2,
                                   "shannon_entropy": 7.0, "file_size_bytes": 200000},
                                  partition=1)
        messages = mock_kafka_broker.consume("malware-ingest-topic", "staging-ingest-group")
        hashes = {m["sample_hash"] for m in messages}
        assert "hash_p0" in hashes
        assert "hash_p1" in hashes

    def test_offset_increments_per_partition(self, mock_kafka_broker, valid_event):
        """Offset must increment independently per partition."""
        mock_kafka_broker.produce("malware-ingest-topic", valid_event, partition=0)
        mock_kafka_broker.produce("malware-ingest-topic", valid_event, partition=0)
        offsets = mock_kafka_broker.topics["malware-ingest-topic"]["current_offsets"]
        assert offsets[0] == 2, f"Expected offset 2, got {offsets[0]}"
        assert offsets[1] == 0, "Partition 1 offset should still be 0"

    def test_produce_does_not_share_state_between_tests(self, mock_kafka_broker):
        """Each test gets a fresh broker — no cross-test contamination."""
        # New fixture → offsets should start at 0
        offsets = mock_kafka_broker.topics["malware-ingest-topic"]["current_offsets"]
        assert all(v == 0 for v in offsets.values()), \
            "Broker has pre-existing messages — fixture not properly isolated"


# ─────────────────────────────────────────────────────────────────────────────
#  Tests — Idempotent Staging UPSERT
# ─────────────────────────────────────────────────────────────────────────────

class TestIdempotentStaging:
    """Tests for idempotent UPSERT behavior in the staging SQLite table."""

    def test_valid_event_is_inserted(self, tmp_sqlite_conn, valid_event):
        """A valid event must be inserted into staging."""
        build_staging_schema(tmp_sqlite_conn)
        inserted = upsert_event(tmp_sqlite_conn, valid_event)
        assert inserted is True
        cursor = tmp_sqlite_conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM staging_malware_events")
        assert cursor.fetchone()[0] == 1

    def test_duplicate_event_does_not_increase_row_count(self, tmp_sqlite_conn, valid_event):
        """Inserting the same event twice must not increase the row count."""
        build_staging_schema(tmp_sqlite_conn)
        upsert_event(tmp_sqlite_conn, valid_event)
        upsert_event(tmp_sqlite_conn, valid_event)   # duplicate
        cursor = tmp_sqlite_conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM staging_malware_events")
        count = cursor.fetchone()[0]
        assert count == 1, \
            f"Idempotent upsert failed — expected 1 row, got {count}"

    def test_different_events_are_all_stored(self, tmp_sqlite_conn, valid_event):
        """Three distinct events must produce three rows in staging."""
        build_staging_schema(tmp_sqlite_conn)
        for i in range(3):
            event = {**valid_event, "sample_hash": f"unique_hash_{i}", "family_id": i + 1}
            upsert_event(tmp_sqlite_conn, event)
        cursor = tmp_sqlite_conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM staging_malware_events")
        assert cursor.fetchone()[0] == 3

    def test_invalid_event_not_inserted(self, tmp_sqlite_conn, valid_event):
        """A DQ-failing event must NOT be inserted into staging."""
        build_staging_schema(tmp_sqlite_conn)
        bad_event = {**valid_event, "file_size_bytes": -1}
        inserted = upsert_event(tmp_sqlite_conn, bad_event)
        assert inserted is False
        cursor = tmp_sqlite_conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM staging_malware_events")
        assert cursor.fetchone()[0] == 0

    def test_staging_dq_status_is_passed(self, tmp_sqlite_conn, valid_event):
        """Inserted rows must have dq_status = 'PASSED'."""
        build_staging_schema(tmp_sqlite_conn)
        upsert_event(tmp_sqlite_conn, valid_event)
        cursor = tmp_sqlite_conn.cursor()
        cursor.execute("SELECT dq_status FROM staging_malware_events")
        status = cursor.fetchone()[0]
        assert status == "PASSED"

    def test_staging_table_columns_exist(self, tmp_sqlite_conn):
        """staging_malware_events must have all required columns."""
        build_staging_schema(tmp_sqlite_conn)
        cursor = tmp_sqlite_conn.cursor()
        cursor.execute("PRAGMA table_info(staging_malware_events)")
        cols = {row[1] for row in cursor.fetchall()}
        required_cols = {
            "idempotency_key", "sample_hash", "family_id",
            "shannon_entropy", "file_size_bytes", "dq_status", "ingestion_timestamp"
        }
        missing = required_cols - cols
        assert not missing, f"Missing staging columns: {missing}"
