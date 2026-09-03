"""
test_phase3_schema.py — Unit tests for Phase 3 OLTP 3NF & OLAP Star Schema.

All tests use the in-memory SQLite fixture (tmp_sqlite_conn) — no disk I/O,
no dependency on physical .db files. Schema is constructed fresh per test.

Tests cover:
  - OLTP table creation (devices, malware_families, scan_logs)
  - OLAP star schema structure (fact + 4 dimension tables)
  - Referential integrity (foreign key constraints)
  - Primary key uniqueness
  - Data insertion and row count accuracy
  - Severity level constraint validation
  - Fact table joins to all dimension tables
"""

import sqlite3
from datetime import datetime, timedelta

import pytest


# ─────────────────────────────────────────────────────────────────────────────
#  Schema builders (mirrors phase3.py create_physical_oltp_db /
#  create_physical_olap_db but operates on an in-memory connection)
# ─────────────────────────────────────────────────────────────────────────────

FAMILY_METADATA = [
    (1, "Ramnit",         "Trojan-Banker",          "HIGH"),
    (2, "Lollipop",       "Adware/PUP",             "MEDIUM"),
    (3, "Kelihos_ver3",   "Botnet/Spam",            "CRITICAL"),
    (4, "Vundo",          "Adware/Downloader",      "HIGH"),
    (5, "Simda",          "Backdoor",               "CRITICAL"),
    (6, "Tracur",         "Trojan-Dropper",         "HIGH"),
    (7, "Kelihos_ver1",   "Botnet/Spam",            "HIGH"),
    (8, "Obfuscator.ACY", "Ransomware/Obfuscated",  "CRITICAL"),
    (9, "Gatak",          "Trojan-Spy",             "HIGH"),
]

VALID_SEVERITY_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def build_oltp_schema(conn: sqlite3.Connection):
    """Create the 3NF OLTP schema in the given connection."""
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            device_id   TEXT PRIMARY KEY,
            hostname    TEXT NOT NULL,
            os_version  TEXT NOT NULL,
            ip_address  TEXT NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS malware_families (
            family_id       INTEGER PRIMARY KEY,
            family_name     TEXT UNIQUE NOT NULL,
            threat_category TEXT NOT NULL,
            severity_level  TEXT NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            scan_id         INTEGER PRIMARY KEY AUTOINCREMENT,
            sample_hash     TEXT NOT NULL,
            device_id       TEXT NOT NULL,
            family_id       INTEGER NOT NULL,
            scan_timestamp  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            shannon_entropy REAL NOT NULL,
            file_size_bytes INTEGER NOT NULL,
            FOREIGN KEY (device_id)  REFERENCES devices(device_id),
            FOREIGN KEY (family_id)  REFERENCES malware_families(family_id)
        );
    """)
    conn.commit()


def build_olap_schema(conn: sqlite3.Connection):
    """Create the Star Schema OLAP tables in the given connection."""
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dim_family (
            family_id       INTEGER PRIMARY KEY,
            family_name     TEXT NOT NULL,
            threat_category TEXT NOT NULL,
            severity_level  TEXT NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dim_device (
            device_id  TEXT PRIMARY KEY,
            hostname   TEXT NOT NULL,
            os_version TEXT NOT NULL,
            ip_address TEXT NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dim_time (
            time_id    INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_date  DATE NOT NULL,
            year       INTEGER NOT NULL,
            month      INTEGER NOT NULL,
            day        INTEGER NOT NULL,
            hour       INTEGER NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dim_engine (
            engine_id   INTEGER PRIMARY KEY AUTOINCREMENT,
            engine_name TEXT UNIQUE NOT NULL,
            vendor      TEXT NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS fact_malware_detections (
            detection_id    INTEGER PRIMARY KEY AUTOINCREMENT,
            family_id       INTEGER NOT NULL,
            device_id       TEXT NOT NULL,
            time_id         INTEGER NOT NULL,
            engine_id       INTEGER NOT NULL,
            shannon_entropy REAL NOT NULL,
            file_size_bytes INTEGER NOT NULL,
            scan_duration_ms REAL,
            FOREIGN KEY (family_id) REFERENCES dim_family(family_id),
            FOREIGN KEY (device_id) REFERENCES dim_device(device_id),
            FOREIGN KEY (time_id)   REFERENCES dim_time(time_id),
            FOREIGN KEY (engine_id) REFERENCES dim_engine(engine_id)
        );
    """)
    conn.commit()


def seed_oltp_data(conn: sqlite3.Connection, n_scans: int = 10):
    """Seed minimal OLTP data for testing queries."""
    cursor = conn.cursor()
    cursor.executemany("INSERT INTO malware_families VALUES (?,?,?,?)", FAMILY_METADATA)
    cursor.execute("INSERT INTO devices VALUES ('DEV-001', 'WKSTN-01', 'Windows 10', '192.168.1.10')")
    base_time = datetime(2024, 1, 1, 10, 0, 0)
    for i in range(n_scans):
        ts = (base_time + timedelta(hours=i)).strftime("%Y-%m-%d %H:%M:%S")
        sql = (
            "INSERT INTO scan_logs "
            "(sample_hash, device_id, family_id, scan_timestamp, shannon_entropy, file_size_bytes) "
            "VALUES (?, ?, ?, ?, ?, ?)"
        )
        cursor.execute(sql, (f"hash_{i:04d}", "DEV-001", (i % 9) + 1, ts, 6.5 + i * 0.05, 500000 + i * 1000))
    conn.commit()


def seed_olap_data(conn: sqlite3.Connection):
    """Seed minimal OLAP data for testing star schema joins."""
    cursor = conn.cursor()
    cursor.executemany("INSERT INTO dim_family VALUES (?,?,?,?)", FAMILY_METADATA)
    cursor.execute("INSERT INTO dim_device VALUES ('DEV-001', 'WKSTN-01', 'Windows 10', '192.168.1.10')")
    cursor.execute("INSERT INTO dim_time (scan_date, year, month, day, hour) VALUES ('2024-01-01', 2024, 1, 1, 10)")
    cursor.execute("INSERT INTO dim_engine (engine_name, vendor) VALUES ('Windows Defender', 'Microsoft')")
    fact_sql = (
        "INSERT INTO fact_malware_detections "
        "(family_id, device_id, time_id, engine_id, shannon_entropy, file_size_bytes) "
        "VALUES (1, 'DEV-001', 1, 1, 6.72, 450000)"
    )
    cursor.execute(fact_sql)
    conn.commit()


# ─────────────────────────────────────────────────────────────────────────────
#  Tests — OLTP 3NF
# ─────────────────────────────────────────────────────────────────────────────

class TestOLTPSchemaCreation:
    """Tests for the 3NF OLTP schema structure."""

    def test_all_oltp_tables_exist(self, tmp_sqlite_conn):
        """All three OLTP tables must be created successfully."""
        build_oltp_schema(tmp_sqlite_conn)
        cursor = tmp_sqlite_conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        for expected_table in ("devices", "malware_families", "scan_logs"):
            assert expected_table in tables, \
                f"OLTP table '{expected_table}' was not created"

    def test_malware_families_has_nine_entries(self, tmp_sqlite_conn):
        """malware_families must contain exactly 9 rows after seeding."""
        build_oltp_schema(tmp_sqlite_conn)
        seed_oltp_data(tmp_sqlite_conn)
        cursor = tmp_sqlite_conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM malware_families")
        count = cursor.fetchone()[0]
        assert count == 9, f"Expected 9 malware families, got {count}"

    def test_scan_logs_row_count(self, tmp_sqlite_conn):
        """scan_logs must contain exactly n_scans rows after seeding."""
        build_oltp_schema(tmp_sqlite_conn)
        seed_oltp_data(tmp_sqlite_conn, n_scans=10)
        cursor = tmp_sqlite_conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scan_logs")
        count = cursor.fetchone()[0]
        assert count == 10, f"Expected 10 scan_logs rows, got {count}"

    def test_device_primary_key_uniqueness(self, tmp_sqlite_conn):
        """Inserting duplicate device_id must raise IntegrityError."""
        build_oltp_schema(tmp_sqlite_conn)
        cursor = tmp_sqlite_conn.cursor()
        cursor.execute("INSERT INTO devices VALUES ('DEV-001', 'HOST-A', 'Win10', '10.0.0.1')")
        with pytest.raises(sqlite3.IntegrityError):
            cursor.execute("INSERT INTO devices VALUES ('DEV-001', 'HOST-B', 'Win11', '10.0.0.2')")

    def test_family_name_uniqueness_constraint(self, tmp_sqlite_conn):
        """Duplicate family_name must raise IntegrityError."""
        build_oltp_schema(tmp_sqlite_conn)
        cursor = tmp_sqlite_conn.cursor()
        cursor.execute("INSERT INTO malware_families VALUES (1, 'Ramnit', 'Trojan', 'HIGH')")
        with pytest.raises(sqlite3.IntegrityError):
            cursor.execute("INSERT INTO malware_families VALUES (2, 'Ramnit', 'Trojan', 'MEDIUM')")

    def test_severity_levels_are_valid(self, tmp_sqlite_conn):
        """All seeded severity levels must be within the allowed set."""
        build_oltp_schema(tmp_sqlite_conn)
        seed_oltp_data(tmp_sqlite_conn)
        cursor = tmp_sqlite_conn.cursor()
        cursor.execute("SELECT DISTINCT severity_level FROM malware_families")
        levels = {row[0] for row in cursor.fetchall()}
        invalid = levels - VALID_SEVERITY_LEVELS
        assert not invalid, f"Invalid severity levels found: {invalid}"

    def test_scan_logs_entropy_range(self, tmp_sqlite_conn):
        """All scan_logs.shannon_entropy values must be within [0, 8]."""
        build_oltp_schema(tmp_sqlite_conn)
        seed_oltp_data(tmp_sqlite_conn, n_scans=20)
        cursor = tmp_sqlite_conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM scan_logs WHERE shannon_entropy < 0 OR shannon_entropy > 8"
        )
        bad_count = cursor.fetchone()[0]
        assert bad_count == 0, \
            f"{bad_count} scan_logs rows have entropy outside [0, 8]"


# ─────────────────────────────────────────────────────────────────────────────
#  Tests — OLAP Star Schema
# ─────────────────────────────────────────────────────────────────────────────

class TestOLAPStarSchema:
    """Tests for the OLAP Star Schema structure and fact/dimension joins."""

    def test_all_olap_tables_exist(self, tmp_sqlite_conn):
        """All 5 OLAP tables (4 dims + 1 fact) must be created."""
        build_olap_schema(tmp_sqlite_conn)
        cursor = tmp_sqlite_conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        for expected in ("dim_family", "dim_device", "dim_time", "dim_engine",
                         "fact_malware_detections"):
            assert expected in tables, f"OLAP table '{expected}' was not created"

    def test_fact_table_joins_all_dimensions(self, tmp_sqlite_conn):
        """The fact table must successfully join all 4 dimension tables."""
        build_olap_schema(tmp_sqlite_conn)
        seed_olap_data(tmp_sqlite_conn)
        cursor = tmp_sqlite_conn.cursor()
        cursor.execute("""
            SELECT f.detection_id, df.family_name, dd.hostname,
                   dt.year, de.engine_name
            FROM fact_malware_detections f
            JOIN dim_family  df ON f.family_id  = df.family_id
            JOIN dim_device  dd ON f.device_id  = dd.device_id
            JOIN dim_time    dt ON f.time_id    = dt.time_id
            JOIN dim_engine  de ON f.engine_id  = de.engine_id
        """)
        rows = cursor.fetchall()
        assert len(rows) == 1, f"Expected 1 joined row, got {len(rows)}"
        detection_id, family_name, hostname, year, engine = rows[0]
        assert family_name == "Ramnit"
        assert hostname == "WKSTN-01"
        assert year == 2024
        assert engine == "Windows Defender"

    def test_dim_family_nine_entries(self, tmp_sqlite_conn):
        """dim_family must contain exactly 9 malware family records."""
        build_olap_schema(tmp_sqlite_conn)
        seed_olap_data(tmp_sqlite_conn)
        cursor = tmp_sqlite_conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM dim_family")
        count = cursor.fetchone()[0]
        assert count == 9, f"Expected 9 dim_family rows, got {count}"

    def test_fact_file_size_positive(self, tmp_sqlite_conn):
        """fact_malware_detections.file_size_bytes must be > 0."""
        build_olap_schema(tmp_sqlite_conn)
        seed_olap_data(tmp_sqlite_conn)
        cursor = tmp_sqlite_conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM fact_malware_detections WHERE file_size_bytes <= 0")
        bad = cursor.fetchone()[0]
        assert bad == 0, f"{bad} fact rows have non-positive file_size_bytes"

    def test_dim_time_fields_populated(self, tmp_sqlite_conn):
        """dim_time rows must have non-null year, month, day, hour."""
        build_olap_schema(tmp_sqlite_conn)
        seed_olap_data(tmp_sqlite_conn)
        cursor = tmp_sqlite_conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM dim_time "
            "WHERE year IS NULL OR month IS NULL OR day IS NULL OR hour IS NULL"
        )
        null_count = cursor.fetchone()[0]
        assert null_count == 0, f"{null_count} dim_time rows have NULL time fields"
