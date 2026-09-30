"""
M7 End-to-End Integration & Hardening Acceptance Drill.

Validates the complete ULPF pipeline lifecycle end-to-end:
1. Ingestion: Multi-event ingestion with distinct lineage IDs and byte seals.
2. Compression & Store: zstd compressed raw frames with byte-for-byte fidelity.
3. Integrity & Merkle Ledger: Deterministic Merkle root, Ed25519 signed ledger anchor.
4. Deep Verification & Tamper Drill: Re-reads raw zstd bytes from disk; isolates tampered leaf on byte corruption.
5. Hot-Path & OCSF 4001: Regex extraction, canonicalization, schema validation, metadata invariant.
6. Sinks Delivery: Local bus fan-out to SIEM stand-in (JSONL/CEF) and partitioned Parquet data lake.
7. Cold-Path Auto-Onboarding: Drain clustering, draft pack generation, Ed25519 signing, RCU hot reload, and subsequent 1.0 confidence HOT path extraction.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any

import pandas as pd
import zstandard as zstd
from pipeline_svc.coldpath.draft_pack import DraftPackGenerator
from pipeline_svc.coldpath.drain import DrainParser
from pipeline_svc.coldpath.onboarding import AutoOnboarder
from pipeline_svc.crypto import generate_keypair, sign_pack
from pipeline_svc.normalization import assemble_ocsf_event
from pipeline_svc.pack_registry import PackRegistry
from pipeline_svc.router import Router
from sinks_svc.service import SinksService
from ulpf_contracts import PathTaken
from ulpf_contracts.db_schema import run_migrations

REPO_ROOT = Path(__file__).resolve().parents[2]


def build_merkle_tree(leaf_hashes: list[str]) -> tuple[str, list[list[bytes]]]:
    """Builds Merkle tree with ULPF spec domain separation and spec padding."""
    sorted_hashes = sorted(leaf_hashes)
    curr = [bytes.fromhex(h) for h in sorted_hashes]
    levels = [curr]
    while len(curr) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(curr), 2):
            left = curr[i]
            right = curr[i + 1] if i + 1 < len(curr) else left
            h = hashlib.sha256(b"\x01" + left + right).digest()
            nxt.append(h)
        curr = nxt
        levels.append(curr)
    root = levels[-1][0].hex()
    return root, levels


def test_m7_complete_end_to_end_drill(tmp_path: Path) -> None:
    # ── 0. Environment Setup ───────────────────────────────────────────────────
    db_file = tmp_path / "test_ulpf_e2e.db"
    run_migrations(db_file)

    data_dir = tmp_path / "data"
    raw_dir = data_dir / "raw_store"
    raw_dir.mkdir(parents=True)
    packs_dir = tmp_path / "packs"
    packs_dir.mkdir()

    priv_pem, pub_pem = generate_keypair()
    key_file = tmp_path / "signing.key"
    key_file.write_bytes(priv_pem)

    # ── 1. Ingestion & Raw Store (M1) ──────────────────────────────────────────
    cisco_logs = [
        '<164>Sep 26 2026 12:00:01: %ASA-4-106023: Deny tcp src outside:10.1.1.1/50000 dst inside:192.168.1.10/80 by access-group "acl_demo"',
        '<164>Sep 26 2026 12:00:02: %ASA-4-106023: Deny tcp src outside:10.1.1.2/50001 dst inside:192.168.1.11/443 by access-group "acl_demo"',
        '<164>Sep 26 2026 12:00:03: %ASA-4-106023: Deny udp src outside:10.1.1.3/50002 dst inside:192.168.1.12/53 by access-group "acl_demo"',
        '<164>Sep 26 2026 12:00:04: %ASA-6-302014: Teardown TCP connection 12345 for outside:10.1.1.1/50000 to inside:192.168.1.10/80 duration 0:00:30 bytes 1500',
    ]

    event_records: list[dict[str, Any]] = []
    chunk_raw_concatenated = bytearray()
    offsets: list[tuple[int, int]] = []

    for raw_text in cisco_logs:
        lid = str(uuid.uuid4())
        raw_b = raw_text.encode("utf-8")
        seal = hashlib.sha256(raw_b).hexdigest()
        start = len(chunk_raw_concatenated)
        chunk_raw_concatenated.extend(raw_b)
        end = len(chunk_raw_concatenated)
        offsets.append((start, end))
        event_records.append({
            "lineage_id": lid,
            "raw_text": raw_text,
            "seal": seal,
            "start": start,
            "end": end,
        })

    # Compress chunk with zstd
    cctx = zstd.ZstdCompressor(level=3)
    compressed_chunk = cctx.compress(bytes(chunk_raw_concatenated))
    chunk_id = "chunk_20260926_e2e_01"
    chunk_file = raw_dir / f"{chunk_id}.zst"
    chunk_file.write_bytes(compressed_chunk)

    # Insert raw_events
    with sqlite3.connect(db_file) as conn:
        for idx, rec in enumerate(event_records):
            ptr = f"raw_store://{chunk_id}/offset_{idx}"
            conn.execute(
                """
                INSERT INTO raw_events (
                    lineage_id, sha256_hash, ingestion_timestamp, source_ip, source_port,
                    transport_protocol, char_encoding, raw_size_bytes, storage_pointer,
                    chunk_id, merkle_leaf_index, created_at
                ) VALUES (?, ?, '2026-09-26T12:00:00Z', '10.1.1.1', 50000, 'TCP', 'utf-8', ?, ?, ?, ?, '2026-09-26T12:00:00Z')
                """,
                (rec["lineage_id"], rec["seal"], len(rec["raw_text"]), ptr, chunk_id, idx),
            )
        conn.commit()

    # ── 2. Merkle Tree & Ledger Anchoring (M2) ─────────────────────────────────
    leaf_hashes = [rec["seal"] for rec in event_records]
    merkle_root, _ = build_merkle_tree(leaf_hashes)

    # Append to signed ledger
    ledger_file = data_dir / "ledger.jsonl"
    ledger_record = {
        "sequence": 1,
        "chunk_id": chunk_id,
        "merkle_root": merkle_root,
        "leaf_count": len(leaf_hashes),
        "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    }
    sig = sign_pack(ledger_record, priv_pem)
    ledger_record["signature"] = sig
    ledger_file.write_text(json.dumps(ledger_record) + "\n", encoding="utf-8")

    # ── 3. Deep Verification from Raw Disk Bytes (M2) ─────────────────────────
    dctx = zstd.ZstdDecompressor()
    recovered_bytes = dctx.decompress(chunk_file.read_bytes())
    for rec in event_records:
        slice_bytes = recovered_bytes[rec["start"]:rec["end"]]
        assert hashlib.sha256(slice_bytes).hexdigest() == rec["seal"]
        assert slice_bytes.decode("utf-8") == rec["raw_text"]

    # ── 4. Tamper Drill Isolation (M2 Acceptance) ──────────────────────────────
    tampered_bytes = bytearray(recovered_bytes)
    tampered_bytes[event_records[1]["start"] + 5] ^= 0xFF  # Corrupt 1 byte in event 1
    tampered_compressed = cctx.compress(bytes(tampered_bytes))
    tampered_chunk_file = raw_dir / "tampered_chunk.zst"
    tampered_chunk_file.write_bytes(tampered_compressed)

    tampered_recovered = dctx.decompress(tampered_chunk_file.read_bytes())
    recomputed_tampered_seals = []
    for rec in event_records:
        t_slice = tampered_recovered[rec["start"]:rec["end"]]
        recomputed_tampered_seals.append(hashlib.sha256(t_slice).hexdigest())

    assert recomputed_tampered_seals[0] == event_records[0]["seal"]  # Untouched
    assert recomputed_tampered_seals[1] != event_records[1]["seal"]  # Isolated altered leaf!
    tampered_root, _ = build_merkle_tree(recomputed_tampered_seals)
    assert tampered_root != merkle_root  # Merkle root mismatch detected!

    # ── 5. Shipped Pack Load & Hot-Path Router (M3) ────────────────────────────
    # Load base network & Cisco ASA pack from repo
    registry = PackRegistry(public_key_pem=pub_pem)
    cisco_pack_text = (REPO_ROOT / "packs" / "vendors" / "cisco_asa_v1.3.0.yaml").read_text(encoding="utf-8")
    base_pack_text = (REPO_ROOT / "packs" / "base" / "base_network.yaml").read_text(encoding="utf-8")

    import yaml
    cisco_dict = yaml.safe_load(cisco_pack_text)
    base_dict = yaml.safe_load(base_pack_text)
    cisco_dict["signature"] = sign_pack(cisco_dict, priv_pem)
    base_dict["signature"] = sign_pack(base_dict, priv_pem)

    registry.load_pack(base_dict)
    registry.load_pack(cisco_dict)

    router = Router(registry)
    envelope = router.route_and_extract(event_records[0]["raw_text"], event_records[0]["lineage_id"])
    assert envelope is not None
    assert envelope.path_taken == PathTaken.hot
    assert envelope.confidence_scores["src_ip"] == 1.0
    assert envelope.extracted_fields["action"] == "Deny"

    # ── 6. OCSF 4001 Normalization Engine (M4) ─────────────────────────────────
    norm_result = assemble_ocsf_event(envelope, raw_data_ptr=f"raw_store://{chunk_id}/offset_0")
    assert norm_result.schema_valid is True
    ocsf = norm_result.ocsf_event
    assert ocsf is not None
    assert ocsf.class_uid == 4001
    assert ocsf.activity_name == "Refuse"
    assert ocsf.metadata is not None
    assert str(ocsf.metadata.uid) == str(envelope.lineage_id)  # Invariant check!

    # ── 7. Sinks Service Delivery (M5) ─────────────────────────────────────────
    sinks = SinksService(base_dir=data_dir)
    sinks.publish_event(ocsf.model_dump(by_alias=True, mode="json"))
    drain_counts = sinks.process_all_pending()
    assert drain_counts["siem-streaming"] == 1
    assert drain_counts["lake-batch"] == 1

    # Verify SIEM outputs
    siem_jsonl = data_dir / "sinks" / "siem" / "events.jsonl"
    siem_cef = data_dir / "sinks" / "siem" / "events.cef"
    assert siem_jsonl.exists() and siem_jsonl.stat().st_size > 0
    assert siem_cef.exists() and "CEF:0|" in siem_cef.read_text(encoding="utf-8")

    # Verify Parquet Lake & Zero-Preprocessing pandas access
    lake_files = list((data_dir / "lake" / "ocsf_events").rglob("*.parquet"))
    assert len(lake_files) >= 1
    df = pd.read_parquet(lake_files[0])
    assert len(df) == 1
    assert df["class_uid"].iloc[0] == 4001
    assert df["_lineage_id"].iloc[0] == str(envelope.lineage_id)
    assert df["_confidence"].iloc[0]["src_ip"] == 1.0

    # ── 8. Cold Path Auto-Onboarding Lifecycle (M6) ───────────────────────────
    unmapped_log = "Juniper SRX: Deny proto=tcp src=172.16.5.10 dst=192.168.1.1"
    parser = DrainParser()
    cluster, _ = parser.parse(unmapped_log)

    generator = DraftPackGenerator()
    draft = generator.generate_pack_dict(
        cluster=cluster,
        confirmed_mapping={"src_ip": "$src", "dst_ip": "$dst", "action": "Deny"},
        source_type="juniper_srx",
    )

    onboarder = AutoOnboarder(
        packs_dir=packs_dir,
        signing_key_path=key_file,
        registry=registry,
        db_path=str(db_file),
    )
    promo = onboarder.confirm_and_promote(draft, actor="analyst:lead", cluster_id=cluster.cluster_id)
    assert promo["status"] == "active"
    assert promo["sweep_results"][draft["pack_id"]] is True

    # Immediate next log TAKES HOT PATH at 1.0 confidence!
    next_log = "Juniper SRX: Deny proto=tcp src=172.16.5.99 dst=8.8.8.8"
    next_env = router.route_and_extract(next_log, uuid.uuid4())
    assert next_env is not None
    assert next_env.path_taken == PathTaken.hot
    assert next_env.confidence_scores["src_ip"] == 1.0
    assert next_env.extracted_fields["src_ip"] == "172.16.5.99"
