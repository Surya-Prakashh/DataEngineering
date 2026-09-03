"""
conftest.py — Shared pytest fixtures for MalwareScope test suite.

All fixtures are available to every test module via pytest's auto-discovery.
Fixtures use in-memory SQLite and mock DataFrames — no disk I/O required,
making the test suite fully portable for CI runners.
"""

import hashlib
import sqlite3
from datetime import datetime

import numpy as np
import pandas as pd
import pytest


# ─────────────────────────────────────────────────────────────────────────────
#  MALWARE FAMILIES CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

MALWARE_FAMILIES = [
    "Ramnit", "Lollipop", "Kelihos_ver3", "Vundo",
    "Tracur", "Kelihos_ver1", "Obfuscator.ACY", "Gatak", "Simda",
]

FAMILY_CLASS_MAP = {f: i + 1 for i, f in enumerate(MALWARE_FAMILIES)}


# ─────────────────────────────────────────────────────────────────────────────
#  FIXTURE: Synthetic Malware DataFrame
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def mock_dataframe() -> pd.DataFrame:
    """
    Returns a synthetic 90-row malware DataFrame covering all 9 families
    (10 rows each) with all required columns — no real CSV needed.
    """
    rng = np.random.default_rng(seed=42)
    rows = []

    # 10 rows per family so all 9 families are represented
    for family in MALWARE_FAMILIES:
        for i in range(10):
            uid = hashlib.sha256(f"{family}_{i}".encode()).hexdigest()[:20]
            size = int(rng.integers(150_000, 12_000_000))
            entropy = round(float(rng.uniform(5.2, 7.95)), 6)
            row = {
                "Id": uid,
                "Class": FAMILY_CLASS_MAP[family],
                "Family_Name": family,
                "BytFSize": size,
                "Total_Bytes": size,
                "Shannon_Entropy": entropy,
                "Null_Byte_Ratio": round(float(rng.uniform(0.01, 0.40)), 6),
                "ASCII_Byte_Ratio": round(float(rng.uniform(0.30, 0.80)), 6),
                "High_Byte_Ratio": round(float(rng.uniform(0.01, 0.30)), 6),
                "NOP_Ratio": round(float(rng.uniform(0.0001, 0.05)), 6),
                "PCA1": round(float(rng.uniform(-5, 5)), 4),
                "PCA2": round(float(rng.uniform(-5, 5)), 4),
                "tSNE1": round(float(rng.uniform(-20, 20)), 4),
                "tSNE2": round(float(rng.uniform(-20, 20)), 4),
            }
            # Add a handful of hex byte-frequency columns
            for hex_byte in ["00", "01", "ff", "20", "0a", "7f", "c0", "80"]:
                row[hex_byte] = round(float(rng.uniform(0, 1000)), 2)
            rows.append(row)

    return pd.DataFrame(rows)


# ─────────────────────────────────────────────────────────────────────────────
#  FIXTURE: Mock Kafka Broker (fresh per test)
# ─────────────────────────────────────────────────────────────────────────────

class _MockKafkaBroker:
    """Minimal in-memory Kafka broker — identical interface to SimulatedKafkaBroker."""

    def __init__(self):
        self.topics = {
            "malware-ingest-topic": {
                "num_partitions": 3,
                "partitions": {0: [], 1: [], 2: []},
                "current_offsets": {0: 0, 1: 0, 2: 0},
            },
            "malware-dlq-topic": {
                "num_partitions": 1,
                "partitions": {0: []},
                "current_offsets": {0: 0},
            },
        }
        self.consumer_groups = {
            "staging-ingest-group": {"offsets": {0: 0, 1: 0, 2: 0}}
        }

    def produce(self, topic_name: str, payload: dict, partition: int = 0):
        if topic_name not in self.topics:
            return None
        offset = self.topics[topic_name]["current_offsets"][partition]
        payload = dict(payload)  # don't mutate caller's dict
        payload["offset"] = offset
        payload["partition"] = partition
        payload["timestamp"] = datetime.now().isoformat()
        self.topics[topic_name]["partitions"][partition].append(payload)
        self.topics[topic_name]["current_offsets"][partition] += 1
        return {"topic": topic_name, "partition": partition, "offset": offset}

    def consume(self, topic_name: str = "malware-ingest-topic",
                group_id: str = "staging-ingest-group"):
        unread = []
        for p, offset in self.consumer_groups[group_id]["offsets"].items():
            all_msgs = self.topics[topic_name]["partitions"][p]
            unread.extend(all_msgs[offset:])
            self.consumer_groups[group_id]["offsets"][p] = len(all_msgs)
        return unread


@pytest.fixture
def mock_kafka_broker() -> _MockKafkaBroker:
    """Fresh isolated Kafka broker per test — no shared state between tests."""
    return _MockKafkaBroker()


# ─────────────────────────────────────────────────────────────────────────────
#  FIXTURE: In-Memory SQLite Database
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_sqlite_conn():
    """
    Provides a transient in-memory SQLite connection.
    Connection is closed automatically after each test.
    """
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON;")
    yield conn
    conn.close()


# ─────────────────────────────────────────────────────────────────────────────
#  FIXTURE: Valid DQ Event
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def valid_event() -> dict:
    """A well-formed Kafka event that should pass all DQ checks."""
    return {
        "message_id": "abc123",
        "sample_hash": "deadbeef01020304",
        "family_id": 3,
        "shannon_entropy": 6.72,
        "file_size_bytes": 450000,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  FIXTURE: Flask Test Client
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def flask_test_client():
    """
    Provides a Flask test client for integration tests.
    Imports app only once per session to avoid heavy CSV/DB re-init.
    """
    from app import app  # noqa: F401 — imported here to avoid top-level side effects
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client
