"""
Worker module for pipeline-svc.
Processes unextracted or specified lineage events through the Router,
OCSF Normalization engine, and Cold-Path Drain/SemanticMapper/ConfidenceGate.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import sqlite3
from datetime import UTC
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


_GLOBAL_DECOMP_CACHE: dict[str, bytes] = {}
_GLOBAL_IDX_CACHE: dict[str, dict[str, Any]] = {}


def process_events(
    lineage_ids: list[str] | None = None,
    db_path: str | None = None,
    lineage_file: str | None = None,
    batch_limit: int = 5000,
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
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA cache_size = -64000")
    conn.execute("PRAGMA temp_store = MEMORY")
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
        # Process unextracted events in high-speed indexed batches
        query = """
            SELECT re.* FROM raw_events re
            LEFT JOIN extraction_history eh ON eh.lineage_id = re.lineage_id
            WHERE eh.extraction_id IS NULL
            ORDER BY re.rowid ASC
            LIMIT ?
        """
        rows = conn.execute(query, (batch_limit,)).fetchall()

    results: list[dict[str, Any]] = []
    if len(_GLOBAL_DECOMP_CACHE) > 50:
        _GLOBAL_DECOMP_CACHE.clear()
        _GLOBAL_IDX_CACHE.clear()

    data_dir_env = os.environ.get("DATA_DIR")
    raw_store_dir = Path(data_dir_env) / "raw_store" if data_dir_env else (
        Path("/app/data/raw_store") if Path("/app/data/raw_store").exists() else REPO_ROOT / "data" / "raw_store"
    )

    conn.execute("BEGIN TRANSACTION")
    try:
        for _idx, row in enumerate(rows):
            lid = row["lineage_id"]
            chunk_id = row["chunk_id"]
            storage_ptr = row["storage_pointer"]
            leaf_idx = row["merkle_leaf_index"]

            raw_text = ""
            offset_key = f"offset_{leaf_idx}"

            if chunk_id:
                if chunk_id not in _GLOBAL_IDX_CACHE:
                    idx_file = raw_store_dir / f"{chunk_id}.idx.json"
                    if idx_file.exists():
                        try:
                            _GLOBAL_IDX_CACHE[chunk_id] = json.loads(idx_file.read_text(encoding="utf-8"))
                        except Exception:
                            _GLOBAL_IDX_CACHE[chunk_id] = {}
                    else:
                        _GLOBAL_IDX_CACHE[chunk_id] = {}

                if chunk_id not in _GLOBAL_DECOMP_CACHE:
                    zst_file = raw_store_dir / f"{chunk_id}.zst"
                    if zst_file.exists():
                        try:
                            _GLOBAL_DECOMP_CACHE[chunk_id] = decompress_zstd_bytes(zst_file.read_bytes())
                        except Exception:
                            _GLOBAL_DECOMP_CACHE[chunk_id] = b""
                    else:
                        _GLOBAL_DECOMP_CACHE[chunk_id] = b""

                idx_data = _GLOBAL_IDX_CACHE.get(chunk_id, {})
                entry = idx_data.get("entries", {}).get(offset_key)
                decomp = _GLOBAL_DECOMP_CACHE.get(chunk_id, b"")
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
                    from datetime import datetime
                    now_str = datetime.now(UTC).isoformat()
                    empty_alts: list[dict[str, Any]] = []
                    cand = {
                        k: {
                            "candidate_ocsf_attribute": k,
                            "similarity_score": envelope.confidence_scores.get(k, 0.85),
                            "alternate_candidates": empty_alts,
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

        conn.execute("COMMIT")
    except Exception:
        with contextlib.suppress(Exception):
            conn.execute("ROLLBACK")
        raise

    conn.close()
    return {"processed_count": len(results), "items": results}


def onboard_cluster(
    cluster_id: str,
    actor: str = "analyst",
    confirmed_mapping: dict[str, Any] | None = None,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Promotes a cluster by generating a named regex pack, signing with Ed25519,
    writing YAML to disk, and RCU hot-reloading."""
    resolved_db = db_path or os.environ.get("DB_PATH") or "ulpf.db"
    db_file = Path(resolved_db) if Path(resolved_db).is_absolute() else REPO_ROOT / resolved_db

    pub_key_env = os.environ.get("VERIFY_KEY_PATH")
    pub_key_path = Path(pub_key_env) if pub_key_env else REPO_ROOT / "keys" / "dev_signing.pub"
    pub_key = pub_key_path.read_bytes() if pub_key_path.exists() else b""

    priv_key_path = REPO_ROOT / "keys" / "dev_signing.key"
    if not priv_key_path.exists() and Path("/app/keys/dev_signing.key").exists():
        priv_key_path = Path("/app/keys/dev_signing.key")

    packs_env = os.environ.get("PACKS_DIR")
    packs_dir = Path(packs_env) if packs_env else REPO_ROOT / "packs"
    vendors_dir = packs_dir / "vendors" if (packs_dir / "vendors").exists() else packs_dir
    vendors_dir.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_file), timeout=30.0)
    conn.row_factory = sqlite3.Row

    # 1. Fetch cluster items to find sample log text
    row = conn.execute(
        """
        SELECT rq.*, eh.source_type, eh.extracted_fields
        FROM review_queue rq
        LEFT JOIN extraction_history eh ON eh.lineage_id = rq.lineage_id
        WHERE rq.cluster_id = ?
        ORDER BY rq.created_at DESC
        LIMIT 1
        """,
        (cluster_id,),
    ).fetchone()

    sample_log = ""
    clean_cid = cluster_id.replace("-", "_")
    source_type = f"onboarded_{clean_cid}"
    if row:
        if row["source_type"] and row["source_type"] != "cold_path_unmapped":
            source_type = row["source_type"]
        ptr = row["sample_raw_pointer"]
        if ptr and ptr.startswith("raw_store://"):
            parts = ptr.replace("raw_store://", "").split("/")
            if len(parts) >= 2:
                chunk_id = parts[0]
                offset_key = parts[1]
                data_dir_env = os.environ.get("DATA_DIR")
                raw_store_dir = Path(data_dir_env) / "raw_store" if data_dir_env else (
                    Path("/app/data/raw_store")
                    if Path("/app/data/raw_store").exists()
                    else REPO_ROOT / "data" / "raw_store"
                )
                idx_file = raw_store_dir / f"{chunk_id}.idx.json"
                zst_file = raw_store_dir / f"{chunk_id}.zst"
                if idx_file.exists() and zst_file.exists():
                    try:
                        idx_data = json.loads(idx_file.read_text(encoding="utf-8"))
                        entry = idx_data.get("entries", {}).get(offset_key)
                        if entry:
                            decomp = decompress_zstd_bytes(zst_file.read_bytes())
                            off = int(entry["offset"])
                            length = int(entry["length"])
                            sample_log = decomp[off:off + length].decode("utf-8", errors="replace")
                    except Exception:
                        pass

    if not sample_log and row:
        raw_row = conn.execute("SELECT * FROM raw_events WHERE lineage_id = ?", (row["lineage_id"],)).fetchone()
        if raw_row:
            sample_log = (
                f"source_ip={raw_row['source_ip']} "
                f"port={raw_row['source_port']} "
                f"proto={raw_row['transport_protocol']}"
            )

    from pipeline_svc.coldpath.draft_pack import DraftPackGenerator
    from pipeline_svc.coldpath.drain import DrainParser
    from pipeline_svc.coldpath.onboarding import AutoOnboarder

    drain = DrainParser()
    cluster, _ = drain.parse(sample_log or f"sample log for {cluster_id}")
    generator = DraftPackGenerator()

    mapping = confirmed_mapping or {}
    if not mapping and row and row["candidate_mapping"]:
        try:
            cand = json.loads(row["candidate_mapping"])
            mapping = {k: f"${k}" for k in cand}
        except Exception:
            pass

    pack_dict = generator.generate_pack_dict(
        cluster=cluster,
        confirmed_mapping=mapping,
        source_type=source_type,
    )

    registry = PackRegistry(public_key_pem=pub_key)
    onboarder = AutoOnboarder(
        packs_dir=packs_dir,
        write_dir=vendors_dir,
        signing_key_path=priv_key_path,
        registry=registry,
        db_path=str(db_file),
    )

    res = onboarder.confirm_and_promote(
        pack_dict=pack_dict,
        actor=actor,
        cluster_id=cluster_id,
    )
    conn.close()
    return res


def main() -> None:
    parser = argparse.ArgumentParser(description="ULPF Pipeline Worker")
    parser.add_argument("--lineage-ids", nargs="*", help="List of lineage IDs to process")
    parser.add_argument("--lineage-file", help="Path to JSON file containing lineage IDs to process")
    parser.add_argument("--db-path", default=None, help="Path to ulpf.db")
    parser.add_argument("--onboard-cluster", help="Cluster ID to onboard and generate signed pack for")
    parser.add_argument("--actor", default="analyst", help="Analyst actor name")
    parser.add_argument("--mapping-json", help="JSON string of confirmed mapping")
    args = parser.parse_args()

    if args.onboard_cluster:
        mapping = json.loads(args.mapping_json) if args.mapping_json else None
        res = onboard_cluster(
            cluster_id=args.onboard_cluster,
            actor=args.actor,
            confirmed_mapping=mapping,
            db_path=args.db_path,
        )
        print(json.dumps(res))
        return

    res = process_events(
        lineage_ids=args.lineage_ids,
        db_path=args.db_path,
        lineage_file=args.lineage_file,
    )
    print(json.dumps(res))


if __name__ == "__main__":
    main()
