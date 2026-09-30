import sqlite3
import uuid
from pathlib import Path

import pytest
from ulpf_contracts import PathTaken

from pipeline_svc.coldpath.confidence_gate import ConfidenceGate
from pipeline_svc.coldpath.draft_pack import DraftPackGenerator
from pipeline_svc.coldpath.drain import DrainParser
from pipeline_svc.coldpath.onboarding import AutoOnboarder, ConflictError
from pipeline_svc.crypto import generate_keypair
from pipeline_svc.pack_registry import PackRegistry
from pipeline_svc.router import Router


def init_test_db(db_path: Path) -> None:
    """Initializes SQLite schema for review_queue, mapping_packs, and pack_lifecycle_events."""
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS review_queue (
            review_id INTEGER PRIMARY KEY AUTOINCREMENT,
            lineage_id TEXT NOT NULL,
            extraction_id INTEGER NOT NULL DEFAULT 0,
            candidate_mapping JSON NOT NULL,
            cluster_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            assigned_analyst TEXT,
            confirmed_mapping JSON,
            created_at TEXT NOT NULL,
            resolved_at TEXT
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS mapping_packs (
            pack_id TEXT PRIMARY KEY,
            version TEXT NOT NULL,
            source_type TEXT NOT NULL,
            pack_yaml_hash TEXT NOT NULL,
            signature TEXT NOT NULL,
            signer_key_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft',
            parent_pack_id TEXT,
            chain_provenance_tx TEXT,
            created_at TEXT NOT NULL,
            promoted_at TEXT
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS pack_lifecycle_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            pack_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            actor TEXT NOT NULL,
            event_hash TEXT NOT NULL,
            chain_tx_hash TEXT,
            occurred_at TEXT NOT NULL
        );
        """)
        conn.commit()


def test_m6_acceptance_1_repeated_unknown_lines_converge_to_stable_template() -> None:
    """M6 Criterion 1: Repeated unknown-format lines converge to one stable template."""
    parser = DrainParser(sim_threshold=0.5)

    samples = [
        "CheckPoint fw: drop packet from 10.0.0.1:1234 to 192.168.1.1:80 proto=tcp",
        "CheckPoint fw: drop packet from 10.0.0.2:5678 to 192.168.1.5:443 proto=tcp",
        "CheckPoint fw: drop packet from 172.16.0.4:9012 to 192.168.1.10:8080 proto=tcp",
        "CheckPoint fw: drop packet from 10.2.2.8:3456 to 192.168.1.20:22 proto=tcp",
    ]

    clusters = []
    for line in samples:
        cluster, is_new = parser.parse(line)
        clusters.append(cluster.cluster_id)

    # All 4 lines must belong to the exact same cluster
    assert len(set(clusters)) == 1
    final_cluster = parser.clusters[0]

    # Template must have stabilized with constant words and wildcard variables
    assert "CheckPoint" in final_cluster.template
    assert "drop" in final_cluster.template
    assert "packet" in final_cluster.template
    assert "<*>" in final_cluster.template
    assert final_cluster.sample_count == 4


def test_m6_acceptance_2_transfer_learning_seeding_accelerates_convergence() -> None:
    """M6 Criterion 2: A similar-vendor format converges measurably faster with seeding than without."""
    # Parser WITHOUT seeding
    unseeded_parser = DrainParser(sim_threshold=0.6)
    c1, is_new1 = unseeded_parser.parse("PaloAlto FW: Deny tcp from 10.1.1.1:1234 to 8.8.8.8:53 rule=DropAll")
    assert is_new1 is True  # Must create a cold cluster from scratch

    # Parser WITH seeding (warm-start transfer learning from base network template)
    seeded_parser = DrainParser(sim_threshold=0.6)
    seeded_parser.add_seed_template("PaloAlto FW: <*> tcp from <*> to <*> rule=<*>")

    c2, is_new2 = seeded_parser.parse("PaloAlto FW: Deny tcp from 10.1.1.1:1234 to 8.8.8.8:53 rule=DropAll")
    # Matches seed cluster immediately (0 iterations needed to discover template structure)
    assert is_new2 is False
    assert c2.is_seed is True
    assert c2.sample_count == 2


def test_m6_acceptance_3_forced_low_similarity_field_lands_in_review_queue(tmp_path: Path) -> None:
    """
    M6 Criterion 3: A forced low-similarity field lands in review_queue (not silently accepted)
    while the event still reaches output flagged in _confidence.
    """
    db_file = tmp_path / "test_ulpf.db"
    init_test_db(db_file)

    gate = ConfidenceGate(threshold=0.85, db_path=str(db_file))
    lineage_id = uuid.uuid4()

    # Field with high score + field with forced low score
    mapped_fields = {
        "src_ip": {
            "candidate_ocsf_attribute": "src_endpoint.ip",
            "similarity_score": 0.95,
            "value": "10.1.1.50",
        },
        "weird_custom_token": {
            "candidate_ocsf_attribute": "action",
            "similarity_score": 0.35,  # Forced low score < 0.85
            "value": "xyzzy_unknown",
        },
    }

    envelope, routed = gate.evaluate_and_route(
        lineage_id=lineage_id,
        source_type="checkpoint_fw",
        cluster_id="drain-cluster-0042",
        mapped_fields=mapped_fields,
    )

    # 1. Flagged and routed to review_queue
    assert routed is True

    # 2. Envelope still emitted for downstream normalization with COLD path
    assert envelope.path_taken == PathTaken.cold
    assert envelope.confidence_scores["src_ip"] == 0.95
    assert envelope.confidence_scores["weird_custom_token"] == 0.35

    # 3. Verify row in SQLite review_queue
    with sqlite3.connect(db_file) as conn:
        row = conn.execute("SELECT lineage_id, cluster_id, status FROM review_queue WHERE lineage_id = ?", (str(lineage_id),)).fetchone()
        assert row is not None
        assert row[0] == str(lineage_id)
        assert row[1] == "drain-cluster-0042"
        assert row[2] == "pending"


def test_m6_acceptance_4_analyst_confirmation_signs_anchors_and_hot_reloads(tmp_path: Path) -> None:
    """
    M6 Criterion 4: One analyst confirmation signs -> anchors -> hot-reloads the pack,
    and the next log of that format takes the hot path at 1.0 confidence.
    """
    db_file = tmp_path / "test_ulpf.db"
    init_test_db(db_file)
    packs_dir = tmp_path / "packs"
    packs_dir.mkdir()

    # Generate keypair
    priv_pem, pub_pem = generate_keypair()
    key_file = tmp_path / "dev_signing.key"
    key_file.write_bytes(priv_pem)

    registry = PackRegistry(public_key_pem=pub_pem)
    router = Router(registry)

    log_sample = "Juniper SRX: Deny proto=tcp src=192.168.1.100 dst=1.1.1.1"
    uid1 = uuid.uuid4()

    # 1. Initial attempt: Hot-path router has no matching pack -> returns None
    env1 = router.route_and_extract(log_sample, uid1, enable_cold_path=False)
    assert env1 is None

    # 2. Cold path mines cluster & generates draft pack
    parser = DrainParser()
    cluster, _ = parser.parse(log_sample)
    generator = DraftPackGenerator()

    draft_pack = generator.generate_pack_dict(
        cluster=cluster,
        confirmed_mapping={"src_ip": "$src", "dst_ip": "$dst", "action": "Deny"},
        source_type="juniper_srx",
    )

    # 3. Analyst confirms: Signs pack, records lifecycle, RCU hot-reloads
    onboarder = AutoOnboarder(
        packs_dir=packs_dir,
        signing_key_path=key_file,
        registry=registry,
        db_path=str(db_file),
    )
    res = onboarder.confirm_and_promote(
        pack_dict=draft_pack,
        actor="analyst:alice",
        cluster_id=cluster.cluster_id,
    )
    assert res["status"] == "active"

    # 4. Immediate next log of this format TAKES THE HOT PATH at 1.0 confidence!
    uid2 = uuid.uuid4()
    env2 = router.route_and_extract(log_sample, uid2)
    assert env2 is not None
    assert env2.path_taken == PathTaken.hot
    assert env2.source_type == "juniper_srx"
    assert env2.confidence_scores["src_ip"] == 1.0
    assert env2.confidence_scores["dst_ip"] == 1.0


def test_m6_acceptance_5_concurrent_confirmations_produce_409_conflict(tmp_path: Path) -> None:
    """M6 Criterion 5: Concurrent confirmations on the same cluster produce a 409 for the loser."""
    db_file = tmp_path / "test_ulpf.db"
    init_test_db(db_file)
    packs_dir = tmp_path / "packs"
    packs_dir.mkdir()

    priv_pem, pub_pem = generate_keypair()
    key_file = tmp_path / "dev_signing.key"
    key_file.write_bytes(priv_pem)

    registry = PackRegistry(public_key_pem=pub_pem)
    onboarder = AutoOnboarder(
        packs_dir=packs_dir,
        signing_key_path=key_file,
        registry=registry,
        db_path=str(db_file),
    )

    pack_dict = {
        "pack_id": "test_concurrent_pack_v1.0.0",
        "version": "1.0.0",
        "source_type": "test_src",
        "regex": r"^test\s+(?P<ip>\S+)$",
        "mapping": {"ip": "$ip"},
    }

    # First analyst confirms successfully
    onboarder.confirm_and_promote(pack_dict, actor="analyst:alice", cluster_id="drain-cluster-0001")

    # Second analyst attempts concurrent confirmation on the same cluster -> 409 Conflict
    with pytest.raises(ConflictError, match="409"):
        onboarder.confirm_and_promote(pack_dict, actor="analyst:bob", cluster_id="drain-cluster-0001")


def test_m6_acceptance_6_cluster_capacity_capping_flags_rather_than_mismerging() -> None:
    """M6 Criterion 6: The cluster-capacity cap flags rather than mis-merges."""
    # Set max_cluster_capacity to 3
    parser = DrainParser(sim_threshold=0.5, max_cluster_capacity=3)

    # Send 3 identical pattern logs -> fills capacity
    for i in range(3):
        parser.parse(f"Log event type A count={i}")

    initial_cluster = parser.clusters[0]
    assert initial_cluster.sample_count == 3
    assert initial_cluster.capacity_capped is False

    # 4th log arrives: capacity cap triggers, flags capacity_capped, and isolates into new branch
    new_cluster, is_new = parser.parse("Log event type A count=999")
    assert initial_cluster.capacity_capped is True
    assert is_new is True
    assert new_cluster.cluster_id != initial_cluster.cluster_id
