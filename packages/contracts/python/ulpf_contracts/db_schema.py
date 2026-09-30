"""ULPF Database Schema — SQLite migrations.

All 8 tables from architecture.md §4, adapted for SQLite per the MVP note:
  - UUID/INET/TIMESTAMPTZ → TEXT (ISO-8601 UTC, microseconds)
  - JSONB → JSON
  - BIGSERIAL → INTEGER PRIMARY KEY AUTOINCREMENT
  - CHECK constraints preserved

History tables (extraction_history, normalization_history, pack_lifecycle_events)
expose only INSERT at the repository layer — no UPDATE/DELETE.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

# ──────────────────────────────────────────────────────────
# Schema DDL
# ──────────────────────────────────────────────────────────

SCHEMA_VERSION = 1

TABLES: list[str] = [
    # ── raw_events ──
    """
    CREATE TABLE IF NOT EXISTS raw_events (
        lineage_id          TEXT PRIMARY KEY,
        sha256_hash         TEXT NOT NULL,
        ingestion_timestamp TEXT NOT NULL,
        source_ip           TEXT NOT NULL,
        source_port         INTEGER NOT NULL,
        transport_protocol  TEXT NOT NULL CHECK (transport_protocol IN ('UDP','TCP','TLS','HTTP')),
        char_encoding       TEXT NOT NULL,
        raw_size_bytes      INTEGER NOT NULL,
        storage_pointer     TEXT NOT NULL,
        chunk_id            TEXT,
        merkle_leaf_index   INTEGER,
        created_at          TEXT NOT NULL
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_raw_events_sha256 ON raw_events(sha256_hash);",
    "CREATE INDEX IF NOT EXISTS idx_raw_events_chunk ON raw_events(chunk_id);",

    # ── merkle_chunks ──
    """
    CREATE TABLE IF NOT EXISTS merkle_chunks (
        chunk_id            TEXT PRIMARY KEY,
        event_count         INTEGER NOT NULL,
        merkle_root_hash    TEXT NOT NULL,
        batch_opened_at     TEXT NOT NULL,
        batch_closed_at     TEXT NOT NULL,
        chain_tx_hash       TEXT,
        chain_block_id      TEXT,
        anchor_status       TEXT NOT NULL DEFAULT 'pending'
                            CHECK (anchor_status IN ('pending','anchored','failed')),
        anchored_at         TEXT
    );
    """,

    # ── extraction_history (append-only) ──
    """
    CREATE TABLE IF NOT EXISTS extraction_history (
        extraction_id       INTEGER PRIMARY KEY AUTOINCREMENT,
        lineage_id          TEXT NOT NULL REFERENCES raw_events(lineage_id),
        path_taken          TEXT NOT NULL CHECK (path_taken IN ('HOT','COLD')),
        source_type         TEXT NOT NULL,
        parser_version      TEXT NOT NULL,
        extracted_fields    JSON NOT NULL,
        confidence_scores   JSON NOT NULL,
        processed_at        TEXT NOT NULL
    );
    """,

    # ── normalization_history (append-only) ──
    """
    CREATE TABLE IF NOT EXISTS normalization_history (
        normalization_id    INTEGER PRIMARY KEY AUTOINCREMENT,
        lineage_id          TEXT NOT NULL REFERENCES raw_events(lineage_id),
        extraction_id       INTEGER NOT NULL REFERENCES extraction_history(extraction_id),
        ocsf_class_uid      INTEGER NOT NULL,
        ocsf_event_json     JSON NOT NULL,
        schema_valid        INTEGER NOT NULL,
        validation_errors   JSON,
        published_to_bus    INTEGER NOT NULL DEFAULT 0,
        normalized_at       TEXT NOT NULL
    );
    """,

    # ── review_queue ──
    """
    CREATE TABLE IF NOT EXISTS review_queue (
        review_id           INTEGER PRIMARY KEY AUTOINCREMENT,
        lineage_id          TEXT NOT NULL,
        extraction_id       INTEGER NOT NULL REFERENCES extraction_history(extraction_id),
        candidate_mapping   JSON NOT NULL,
        cluster_id          TEXT NOT NULL,
        status              TEXT NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending','in_review','confirmed','rejected')),
        assigned_analyst    TEXT,
        confirmed_mapping   JSON,
        created_at          TEXT NOT NULL,
        resolved_at         TEXT
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_review_queue_lineage ON review_queue(lineage_id);",
    "CREATE INDEX IF NOT EXISTS idx_review_queue_cluster ON review_queue(cluster_id);",

    # ── mapping_packs ──
    """
    CREATE TABLE IF NOT EXISTS mapping_packs (
        pack_id             TEXT PRIMARY KEY,
        source_type         TEXT NOT NULL,
        version             TEXT NOT NULL,
        pack_yaml_hash      TEXT NOT NULL,
        signature           TEXT NOT NULL,
        signer_key_id       TEXT NOT NULL,
        status              TEXT NOT NULL DEFAULT 'draft'
                            CHECK (status IN ('draft','staged','quarantined','active','deprecated')),
        parent_pack_id      TEXT REFERENCES mapping_packs(pack_id),
        chain_provenance_tx TEXT,
        created_at          TEXT NOT NULL,
        promoted_at         TEXT
    );
    """,

    # ── pack_lifecycle_events (append-only) ──
    """
    CREATE TABLE IF NOT EXISTS pack_lifecycle_events (
        event_id            INTEGER PRIMARY KEY AUTOINCREMENT,
        pack_id             TEXT NOT NULL REFERENCES mapping_packs(pack_id),
        event_type          TEXT NOT NULL
                            CHECK (event_type IN (
                                'pack_created','pack_confirmed','pack_updated',
                                'pack_rolled_back','pack_quarantined'
                            )),
        actor               TEXT NOT NULL,
        event_hash          TEXT NOT NULL,
        chain_tx_hash       TEXT,
        occurred_at         TEXT NOT NULL
    );
    """,

    # ── test_fixtures ──
    """
    CREATE TABLE IF NOT EXISTS test_fixtures (
        fixture_id          INTEGER PRIMARY KEY AUTOINCREMENT,
        pack_id             TEXT NOT NULL REFERENCES mapping_packs(pack_id),
        sample_raw_pointer  TEXT NOT NULL,
        expected_ocsf_json  JSON NOT NULL,
        created_at          TEXT NOT NULL
    );
    """,

    # ── schema_version tracking ──
    """
    CREATE TABLE IF NOT EXISTS _schema_version (
        version INTEGER NOT NULL,
        applied_at TEXT NOT NULL
    );
    """,
]


# ──────────────────────────────────────────────────────────
# Migration runner
# ──────────────────────────────────────────────────────────

def get_current_version(conn: sqlite3.Connection) -> int:
    """Return the current schema version, or 0 if the table doesn't exist."""
    try:
        row = conn.execute(
            "SELECT MAX(version) FROM _schema_version"
        ).fetchone()
        return row[0] if row and row[0] is not None else 0
    except sqlite3.OperationalError:
        return 0


def run_migrations(db_path: str | Path = "ulpf.db") -> None:
    """Apply all pending migrations to the given SQLite database."""
    db_path = Path(db_path)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")

    current = get_current_version(conn)
    if current >= SCHEMA_VERSION:
        print(f"Database already at version {current}, nothing to do.")
        conn.close()
        return

    print(f"Migrating database from version {current} to {SCHEMA_VERSION}...")

    for ddl in TABLES:
        conn.execute(ddl)


    now = datetime.now(UTC).isoformat()
    conn.execute(
        "INSERT INTO _schema_version (version, applied_at) VALUES (?, ?)",
        (SCHEMA_VERSION, now),
    )
    conn.commit()
    conn.close()
    print(f"Migration complete. Database: {db_path}")


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "ulpf.db"
    run_migrations(path)
