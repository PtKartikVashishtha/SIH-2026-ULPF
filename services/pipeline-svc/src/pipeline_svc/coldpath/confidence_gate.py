"""
Confidence Gate & Review Queue Router for ULPF Cold Path (M6).

Evaluates semantic mapping scores against a configurable threshold (default 0.85).
Any low-confidence field (< 0.85) is routed to SQLite `review_queue` for analyst review,
while still emitting a COLD-path ExtractionEnvelope so the event reaches downstream output.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime
from typing import Any

from ulpf_contracts import ExtractionEnvelope, PathTaken


class ConfidenceGate:
    """Evaluates field confidence scores and enqueues low-confidence logs into `review_queue`."""

    def __init__(
        self,
        threshold: float = 0.85,
        db_path: str = "ulpf.db",
        conn: sqlite3.Connection | None = None,
    ) -> None:
        self.threshold = threshold
        self.db_path = db_path
        self._shared_conn = conn

    def evaluate_and_route(
        self,
        lineage_id: str | uuid.UUID,
        source_type: str,
        cluster_id: str,
        mapped_fields: dict[str, dict[str, Any]],
        extraction_id: int = 0,
        parser_version: str = "0.1.0-cold",
        sample_raw_pointer: str | None = None,
    ) -> tuple[ExtractionEnvelope, bool]:
        """
        Evaluates mapped fields.
        If any field has score < threshold or source_type is cold_path_unmapped:
          - Inserts record into `review_queue` table
          - Returns envelope with path_taken=COLD and routed_to_review_queue=True
        Otherwise:
          - Returns envelope with path_taken=COLD and routed_to_review_queue=False
        """
        str_lineage = str(lineage_id)
        extracted_fields: dict[str, str] = {}
        confidence_scores: dict[str, float] = {}

        has_low_confidence = False
        candidate_mapping: dict[str, Any] = {}

        for raw_key, info in mapped_fields.items():
            attr = info["candidate_ocsf_attribute"]
            score = float(info["similarity_score"])
            val = str(info["value"])

            extracted_fields[raw_key] = val
            confidence_scores[raw_key] = score

            # Normalize canonical aliases so downstream normalizer receives standard keys
            if attr == "src_endpoint.ip" and "src_ip" not in extracted_fields:
                extracted_fields["src_ip"] = val
                confidence_scores["src_ip"] = score
            elif attr == "dst_endpoint.ip" and "dst_ip" not in extracted_fields:
                extracted_fields["dst_ip"] = val
                confidence_scores["dst_ip"] = score
            elif attr == "src_endpoint.port" and "src_port" not in extracted_fields:
                extracted_fields["src_port"] = val
                confidence_scores["src_port"] = score
            elif attr == "dst_endpoint.port" and "dst_port" not in extracted_fields:
                extracted_fields["dst_port"] = val
                confidence_scores["dst_port"] = score
            elif attr == "connection_info.protocol_name" and "protocol" not in extracted_fields:
                extracted_fields["protocol"] = val
                confidence_scores["protocol"] = score
            elif attr == "action" and "action" not in extracted_fields:
                extracted_fields["action"] = val
                confidence_scores["action"] = score

            candidate_mapping[raw_key] = {
                "candidate_ocsf_attribute": attr,
                "similarity_score": score,
                "alternate_candidates": info.get("alternate_candidates", []),
            }

            if score < self.threshold:
                has_low_confidence = True

        if not mapped_fields:
            has_low_confidence = True

        routed_to_review_queue = False
        if has_low_confidence or source_type == "cold_path_unmapped":
            routed_to_review_queue = True
            self._enqueue_for_review(
                lineage_id=str_lineage,
                extraction_id=extraction_id,
                cluster_id=cluster_id,
                candidate_mapping=candidate_mapping,
                sample_raw_pointer=sample_raw_pointer,
            )

        envelope = ExtractionEnvelope(
            lineage_id=uuid.UUID(str_lineage),
            path_taken=PathTaken.cold,
            source_type=source_type,
            extracted_fields=extracted_fields,
            confidence_scores=confidence_scores,
            parser_version=parser_version,
        )

        return envelope, routed_to_review_queue

    def _enqueue_for_review(
        self,
        lineage_id: str,
        extraction_id: int,
        cluster_id: str,
        candidate_mapping: dict[str, Any],
        sample_raw_pointer: str | None = None,
    ) -> None:
        """Records the pending review item into SQLite review_queue table."""
        now = datetime.now(UTC).isoformat()
        try:
            if self._shared_conn is not None:
                self._shared_conn.execute(
                    """
                    INSERT INTO review_queue (
                        lineage_id, extraction_id, candidate_mapping, cluster_id,
                        status, created_at, sample_raw_pointer
                    ) VALUES (?, ?, ?, ?, 'pending', ?, ?)
                    """,
                    (
                        lineage_id,
                        extraction_id,
                        json.dumps(candidate_mapping),
                        cluster_id,
                        now,
                        sample_raw_pointer,
                    ),
                )
            else:
                with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                    conn.execute(
                        """
                        INSERT INTO review_queue (
                            lineage_id, extraction_id, candidate_mapping, cluster_id,
                            status, created_at, sample_raw_pointer
                        ) VALUES (?, ?, ?, ?, 'pending', ?, ?)
                        """,
                        (
                            lineage_id,
                            extraction_id,
                            json.dumps(candidate_mapping),
                            cluster_id,
                            now,
                            sample_raw_pointer,
                        ),
                    )
                    conn.commit()
        except sqlite3.OperationalError:
            # Fallback for schemas without sample_raw_pointer column
            try:
                if self._shared_conn is not None:
                    self._shared_conn.execute(
                        """
                        INSERT INTO review_queue (
                            lineage_id, extraction_id, candidate_mapping, cluster_id,
                            status, created_at
                        ) VALUES (?, ?, ?, ?, 'pending', ?)
                        """,
                        (lineage_id, extraction_id, json.dumps(candidate_mapping), cluster_id, now),
                    )
                else:
                    with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                        conn.execute(
                            """
                            INSERT INTO review_queue (
                                lineage_id, extraction_id, candidate_mapping, cluster_id,
                                status, created_at
                            ) VALUES (?, ?, ?, ?, 'pending', ?)
                            """,
                            (lineage_id, extraction_id, json.dumps(candidate_mapping), cluster_id, now),
                        )
                        conn.commit()
            except Exception:
                pass
