"""
Worker module for pipeline-svc.
Processes unextracted or specified lineage events through the Router,
OCSF Normalization engine, and Cold-Path Drain/SemanticMapper/ConfidenceGate.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

from pipeline_svc.coldpath.confidence_gate import ConfidenceGate
from pipeline_svc.coldpath.drain import DrainParser
from pipeline_svc.coldpath.semantic_mapper import SemanticMapper
from pipeline_svc.db import SqlitePipelineRepository
from pipeline_svc.normalization import normalize_and_record
from pipeline_svc.pack_registry import PackRegistry
from pipeline_svc.router import Router

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
if not (REPO_ROOT / "packs").exists():
    REPO_ROOT = Path("/app")


def decompress_zstd_bytes(compressed_bytes: bytes) -> bytes:
    try:
        import zstandard as zstd
        return zstd.ZstdDecompressor().decompress(compressed_bytes)
    except Exception:
        pass

    import ctypes
    so_paths = [
        "/usr/lib/x86_64-linux-gnu/libzstd.so.1",
        "/usr/lib/libzstd.so.1",
        "/lib/x86_64-linux-gnu/libzstd.so.1",
        "libzstd.so.1",
        "libzstd.so",
    ]
    for p in so_paths:
        try:
            lib = ctypes.CDLL(p)
            lib.ZSTD_decompress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
            lib.ZSTD_decompress.restype = ctypes.c_size_t
            lib.ZSTD_getFrameContentSize.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            lib.ZSTD_getFrameContentSize.restype = ctypes.c_ulonglong

            content_size = lib.ZSTD_getFrameContentSize(compressed_bytes, len(compressed_bytes))
            if content_size == 0 or content_size > 100_000_000:
                content_size = len(compressed_bytes) * 10
            buf = ctypes.create_string_buffer(content_size)
            decomp_len = lib.ZSTD_decompress(buf, content_size, compressed_bytes, len(compressed_bytes))
            if decomp_len > 0:
                return buf.raw[:decomp_len]
        except Exception:
            continue
    return b""


def process_events(
    lineage_ids: list[str] | None = None,
    db_path: str | None = None,
    lineage_file: str | None = None,
) -> dict[str, Any]:
    resolved_db = db_path or os.environ.get("DB_PATH") or "ulpf.db"
    db_file = Path(resolved_db) if Path(resolved_db).is_absolute() else REPO_ROOT / resolved_db

    pub_key_env = os.environ.get("VERIFY_KEY_PATH")
    pub_key_path = Path(pub_key_env) if pub_key_env else REPO_ROOT / "keys" / "dev_signing.pub"
    pub_key = pub_key_path.read_bytes() if pub_key_path.exists() else b""

    packs_env = os.environ.get("PACKS_DIR")
    packs_dir = Path(packs_env) if packs_env else REPO_ROOT / "packs"

    registry = PackRegistry(public_key_pem=pub_key)
    registry.reconcile_sweep(packs_dir)

    conn = sqlite3.connect(str(db_file), timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")

    # Find highest existing drain-cluster sequence to avoid colliding with seed clusters
    existing_cids = [r[0] for r in conn.execute("SELECT DISTINCT cluster_id FROM review_queue").fetchall() if r[0]]
    max_seq = 10
    for cid in existing_cids:
        if cid.startswith("drain-cluster-"):
            try:
                seq = int(cid.split("-")[-1])
                max_seq = max(max_seq, seq)
            except ValueError:
                pass
    next_seq = max_seq + 1

    drain_parser = DrainParser(initial_sequence=next_seq)
    semantic_mapper = SemanticMapper()
    confidence_gate = ConfidenceGate(db_path=str(db_file), threshold=0.85, conn=conn)

    router = Router(
        registry=registry,
        drain_parser=drain_parser,
        semantic_mapper=semantic_mapper,
        confidence_gate=confidence_gate,
    )

    repo = SqlitePipelineRepository(str(db_file), conn=conn)

    class LocalBus:
        def __init__(self) -> None:
            self.events: list[tuple[str, dict[str, Any]]] = []

        def publish(self, topic: str, msg: dict[str, Any]) -> None:
            self.events.append((topic, msg))

    bus = LocalBus()

    if lineage_file and Path(lineage_file).exists():
        raw_content = Path(lineage_file).read_text(encoding="utf-8").strip()
        try:
            lineage_ids = json.loads(raw_content)
        except Exception:
            lineage_ids = [line.strip() for line in raw_content.splitlines() if line.strip()]

    rows = []
    if lineage_ids:
        for i in range(0, len(lineage_ids), 500):
            batch = lineage_ids[i:i + 500]
            placeholders = ",".join("?" for _ in batch)
            query = f"SELECT * FROM raw_events WHERE lineage_id IN ({placeholders})"
            rows.extend(conn.execute(query, batch).fetchall())
    else:
        # Process all events in raw_events that do not have an extraction_history record yet
        query = """
            SELECT re.* FROM raw_events re
            LEFT JOIN extraction_history eh ON eh.lineage_id = re.lineage_id
            WHERE eh.extraction_id IS NULL
            ORDER BY re.created_at ASC
        """
        rows = conn.execute(query).fetchall()

    results: list[dict[str, Any]] = []
    decomp_cache: dict[str, bytes] = {}
    idx_cache: dict[str, dict[str, Any]] = {}

    data_dir_env = os.environ.get("DATA_DIR")
    raw_store_dir = Path(data_dir_env) / "raw_store" if data_dir_env else (
        Path("/app/data/raw_store") if Path("/app/data/raw_store").exists() else REPO_ROOT / "data" / "raw_store"
    )

    for idx, row in enumerate(rows):
        lid = row["lineage_id"]
        chunk_id = row["chunk_id"]
        storage_ptr = row["storage_pointer"]
        leaf_idx = row["merkle_leaf_index"]

        raw_text = ""
        offset_key = f"offset_{leaf_idx}"

        if chunk_id:
            if chunk_id not in idx_cache:
                idx_file = raw_store_dir / f"{chunk_id}.idx.json"
                if idx_file.exists():
                    try:
                        idx_cache[chunk_id] = json.loads(idx_file.read_text(encoding="utf-8"))
                    except Exception:
                        idx_cache[chunk_id] = {}
                else:
                    idx_cache[chunk_id] = {}

            if chunk_id not in decomp_cache:
                zst_file = raw_store_dir / f"{chunk_id}.zst"
                if zst_file.exists():
                    try:
                        decomp_cache[chunk_id] = decompress_zstd_bytes(zst_file.read_bytes())
                    except Exception:
                        decomp_cache[chunk_id] = b""
                else:
                    decomp_cache[chunk_id] = b""

            idx_data = idx_cache.get(chunk_id, {})
            entry = idx_data.get("entries", {}).get(offset_key)
            decomp = decomp_cache.get(chunk_id, b"")
            if entry and decomp:
                off = int(entry["offset"])
                length = int(entry["length"])
                raw_text = decomp[off:off + length].decode("utf-8", errors="replace")

        # Fallback raw text if chunk wasn't readable
        if not raw_text:
            raw_text = f"source_ip={row['source_ip']} port={row['source_port']} proto={row['transport_protocol']}"

        envelope = router.route_and_extract(raw_text, lid, enable_cold_path=True, sample_raw_pointer=storage_ptr)

        if envelope:
            ext_id = repo.record_extraction(envelope)
            path_taken = getattr(envelope.path_taken, "value", str(envelope.path_taken))

            # If hot path, normalize to OCSF
            if path_taken.upper() == "HOT":
                try:
                    norm_res, _ = normalize_and_record(
                        envelope,
                        extraction_id=ext_id,
                        repo=repo,
                        bus=bus,  # type: ignore[arg-type]
                        raw_data_ptr=storage_ptr,
                    )
                    results.append({
                        "lineage_id": lid,
                        "path_taken": "HOT",
                        "source_type": envelope.source_type,
                        "normalized": norm_res.schema_valid,
                        "ocsf_class": norm_res.ocsf_event.class_uid if norm_res.ocsf_event else None,
                    })
                except Exception as ex:  # noqa: BLE001
                    results.append({
                        "lineage_id": lid,
                        "path_taken": "HOT",
                        "source_type": envelope.source_type,
                        "error": str(ex),
                    })
            else:
                # Cold path: Drain cluster or review queue
                cur = conn.execute(
                    "UPDATE review_queue SET extraction_id = ?, sample_raw_pointer = ? WHERE lineage_id = ?",
                    (ext_id, storage_ptr, lid),
                )
                if cur.rowcount == 0:
                    from datetime import datetime, timezone
                    now_str = datetime.now(timezone.utc).isoformat()
                    cand = {
                        k: {
                            "candidate_ocsf_attribute": k,
                            "similarity_score": envelope.confidence_scores.get(k, 0.85),
                            "alternate_candidates": [],
                        }
                        for k in envelope.extracted_fields
                    }
                    cid = f"drain-cluster-{next_seq:04d}"
                    conn.execute(
                        """
                        INSERT INTO review_queue (
                            lineage_id, extraction_id, candidate_mapping, cluster_id,
                            status, created_at, sample_raw_pointer
                        ) VALUES (?, ?, ?, ?, 'pending', ?, ?)
                        """,
                        (lid, ext_id, json.dumps(cand), cid, now_str, storage_ptr),
                    )

                results.append({
                    "lineage_id": lid,
                    "path_taken": "COLD",
                    "source_type": envelope.source_type,
                    "fields_extracted": len(envelope.extracted_fields),
                })
        else:
            results.append({
                "lineage_id": lid,
                "path_taken": "RAW",
                "source_type": "unknown",
            })

    conn.close()
    return {"processed_count": len(results), "items": results}


def main() -> None:
    parser = argparse.ArgumentParser(description="ULPF Pipeline Worker")
    parser.add_argument("--lineage-ids", nargs="*", help="List of lineage IDs to process")
    parser.add_argument("--lineage-file", help="Path to JSON file containing lineage IDs to process")
    parser.add_argument("--db-path", default=None, help="Path to ulpf.db")
    args = parser.parse_args()

    res = process_events(
        lineage_ids=args.lineage_ids,
        db_path=args.db_path,
        lineage_file=args.lineage_file,
    )
    print(json.dumps(res))


if __name__ == "__main__":
    main()
