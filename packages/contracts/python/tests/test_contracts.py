"""Round-trip validation tests for ULPF contracts.

M0 acceptance criteria: "A sample payload for each contract round-trips
(encode → validate → decode) in both Python and TypeScript against
the *same* generated types."

This file covers the Python side.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from ulpf_contracts import (
    ErrorResponse,
    ExtractionEnvelope,
    MerkleLeafV1,
    OcsfNetworkActivityV1,
    PackLifecycleV1,
    RawIngestV1,
    ReviewQueueV1,
)

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas"


def _load_schema(name: str) -> dict:
    """Load a JSON Schema file from the schemas directory."""
    path = SCHEMA_DIR / name
    return json.loads(path.read_text())


# ──────────────────────────────────────────────────────────
# Sample payloads
# ──────────────────────────────────────────────────────────

SAMPLE_RAW_INGEST = {
    "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
    "raw_bytes_b64": "SEVMTE8gV09STEQ=",
    "storage_pointer": "raw_store://chunk_20260925_01/offset_42",
    "sha256_hash": "a" * 64,
    "ingestion_timestamp": "2026-09-25T09:12:44.123456Z",
    "source_ip": "203.0.113.5",
    "source_port": 51422,
    "transport_protocol": "UDP",
    "char_encoding": "UTF-8",
}

SAMPLE_MERKLE_LEAF = {
    "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
    "sha256_hash": "b" * 64,
    "ingestion_timestamp": "2026-09-25T09:12:44.123456Z",
}

SAMPLE_EXTRACTION_ENVELOPE = {
    "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
    "path_taken": "HOT",
    "source_type": "cisco_asa",
    "extracted_fields": {"src_ip": "10.1.1.1", "dst_ip": "8.8.8.8", "action": "Deny"},
    "confidence_scores": {"src_ip": 1.0, "dst_ip": 1.0, "action": 0.95},
    "parser_version": "1.3.0",
}

SAMPLE_REVIEW_QUEUE = {
    "review_id": None,
    "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
    "extraction_id": 1,
    "cluster_id": "drain-cluster-0042",
    "candidate_mapping": {
        "field_raw_token_3": {
            "candidate_ocsf_attribute": "dst_endpoint.hostname",
            "similarity_score": 0.71,
            "alternate_candidates": [
                {"attribute": "src_endpoint.hostname", "similarity_score": 0.68}
            ],
        }
    },
    "sample_raw_pointer": "raw_store://chunk_20260925_01/offset_42",
}

SAMPLE_PACK_LIFECYCLE = {
    "pack_id": "cisco_asa_v1.3.0",
    "event_type": "pack_created",
    "actor": "analyst:jdoe",
    "event_hash": "c" * 64,
    "occurred_at": "2026-09-25T09:12:44Z",
}

LINEAGE_ID = "550e8400-e29b-41d4-a716-446655440000"

SAMPLE_OCSF_EVENT = {
    "activity_id": 5,
    "activity_name": "Refuse",
    "category_uid": 4,
    "class_uid": 4001,
    "class_name": "Network Activity",
    "severity_id": 4,
    "time": 1790328764123,
    "src_endpoint": {"ip": "10.1.1.50", "port": 49823},
    "dst_endpoint": {"ip": "8.8.8.8", "port": 443},
    "connection_info": {"protocol_num": 6, "protocol_name": "tcp"},
    "metadata": {
        "version": "1.2.0",
        "uid": LINEAGE_ID,
        "product": {"vendor_name": "Cisco", "name": "ASA Firewall"},
    },
    "raw_data": "raw_store://chunk_20260925_01/offset_42",
    "_confidence": {"src_endpoint.ip": 1.0, "activity_id": 0.95},
    "_lineage_id": LINEAGE_ID,
}

SAMPLE_ERROR_RESPONSE = {
    "error": {
        "code": "CONFLICT",
        "message": "Another analyst already confirmed this cluster.",
        "details": {"winner": "analyst:alice"},
    }
}


# ──────────────────────────────────────────────────────────
# Tests: Pydantic round-trip (encode → JSON → decode)
# ──────────────────────────────────────────────────────────


class TestRawIngestV1:
    def test_round_trip(self) -> None:
        model = RawIngestV1.model_validate(SAMPLE_RAW_INGEST)
        dumped = json.loads(model.model_dump_json())
        reparsed = RawIngestV1.model_validate(dumped)
        assert str(reparsed.lineage_id) == SAMPLE_RAW_INGEST["lineage_id"]
        assert reparsed.sha256_hash == SAMPLE_RAW_INGEST["sha256_hash"]
        assert reparsed.source_port == SAMPLE_RAW_INGEST["source_port"]

    def test_schema_validation(self) -> None:
        schema = _load_schema("raw_ingest.v1.schema.json")
        jsonschema.validate(instance=SAMPLE_RAW_INGEST, schema=schema)


class TestMerkleLeafV1:
    def test_round_trip(self) -> None:
        model = MerkleLeafV1.model_validate(SAMPLE_MERKLE_LEAF)
        dumped = json.loads(model.model_dump_json())
        reparsed = MerkleLeafV1.model_validate(dumped)
        assert str(reparsed.lineage_id) == SAMPLE_MERKLE_LEAF["lineage_id"]

    def test_schema_validation(self) -> None:
        schema = _load_schema("merkle_leaf.v1.schema.json")
        jsonschema.validate(instance=SAMPLE_MERKLE_LEAF, schema=schema)


class TestExtractionEnvelope:
    def test_round_trip(self) -> None:
        model = ExtractionEnvelope.model_validate(SAMPLE_EXTRACTION_ENVELOPE)
        dumped = json.loads(model.model_dump_json())
        reparsed = ExtractionEnvelope.model_validate(dumped)
        assert reparsed.path_taken.value == "HOT"
        assert reparsed.source_type == "cisco_asa"

    def test_schema_validation(self) -> None:
        schema = _load_schema("extraction_envelope.schema.json")
        jsonschema.validate(instance=SAMPLE_EXTRACTION_ENVELOPE, schema=schema)


class TestReviewQueueV1:
    def test_round_trip(self) -> None:
        model = ReviewQueueV1.model_validate(SAMPLE_REVIEW_QUEUE)
        dumped = json.loads(model.model_dump_json())
        reparsed = ReviewQueueV1.model_validate(dumped)
        assert reparsed.cluster_id == "drain-cluster-0042"

    def test_schema_validation(self) -> None:
        schema = _load_schema("review_queue.v1.schema.json")
        jsonschema.validate(instance=SAMPLE_REVIEW_QUEUE, schema=schema)


class TestPackLifecycleV1:
    def test_round_trip(self) -> None:
        model = PackLifecycleV1.model_validate(SAMPLE_PACK_LIFECYCLE)
        dumped = json.loads(model.model_dump_json())
        reparsed = PackLifecycleV1.model_validate(dumped)
        assert reparsed.pack_id == "cisco_asa_v1.3.0"
        assert reparsed.event_type.value == "pack_created"

    def test_schema_validation(self) -> None:
        schema = _load_schema("pack_lifecycle.v1.schema.json")
        jsonschema.validate(instance=SAMPLE_PACK_LIFECYCLE, schema=schema)


class TestOcsfNetworkActivityV1:
    def test_round_trip(self) -> None:
        model = OcsfNetworkActivityV1.model_validate(SAMPLE_OCSF_EVENT)
        dumped = json.loads(model.model_dump_json(by_alias=True))
        reparsed = OcsfNetworkActivityV1.model_validate(dumped)
        assert str(reparsed.field_lineage_id) == LINEAGE_ID
        assert reparsed.class_uid == 4001
        assert str(reparsed.metadata.uid) == LINEAGE_ID

    def test_schema_validation(self) -> None:
        schema = _load_schema("ocsf_event.v1.schema.json")
        jsonschema.validate(instance=SAMPLE_OCSF_EVENT, schema=schema)


class TestErrorResponse:
    def test_round_trip(self) -> None:
        model = ErrorResponse.model_validate(SAMPLE_ERROR_RESPONSE)
        dumped = json.loads(model.model_dump_json())
        reparsed = ErrorResponse.model_validate(dumped)
        assert reparsed.error.code == "CONFLICT"

    def test_schema_validation(self) -> None:
        schema = _load_schema("error_response.schema.json")
        jsonschema.validate(instance=SAMPLE_ERROR_RESPONSE, schema=schema)


# ──────────────────────────────────────────────────────────
# Test: DB schema migration
# ──────────────────────────────────────────────────────────

class TestDbSchema:
    def test_migration_creates_all_tables(self, tmp_path: Path) -> None:
        import sqlite3

        from ulpf_contracts.db_schema import run_migrations

        db_path = tmp_path / "test.db"
        run_migrations(db_path)

        conn = sqlite3.connect(str(db_path))
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        conn.close()

        expected = {
            "raw_events",
            "merkle_chunks",
            "extraction_history",
            "normalization_history",
            "review_queue",
            "mapping_packs",
            "pack_lifecycle_events",
            "test_fixtures",
            "_schema_version",
        }
        assert expected.issubset(tables), f"Missing tables: {expected - tables}"

    def test_migration_is_idempotent(self, tmp_path: Path) -> None:
        from ulpf_contracts.db_schema import run_migrations

        db_path = tmp_path / "test.db"
        run_migrations(db_path)
        run_migrations(db_path)  # Should not fail
