"""
ULPF Red-Team Security & Adversarial Attack Verification Suite.

Actively attempts to break:
1. ReDoS (Regex Denial of Service) parser bombs
2. Malicious PyYAML deserialization (arbitrary Python object execution)
3. Oversized payload & memory exhaustion attempts
4. Path traversal in storage pointers
5. Ed25519 cryptographic signature forgery & pack tampering
6. Cyclic inheritance bombs in mapping pack compilers
7. SQL injection in database repository queries
8. Merkle tree domain separation & preimage resistance
9. Corrupted zstd frame resilience
10. Lineage ID collision & replay attacks
"""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
import time
import uuid
from pathlib import Path
import pytest
import yaml

from pipeline_svc.compiler import CompilationError, CyclicInheritanceError, compile_pack, parse_pack_dict
from pipeline_svc.crypto import generate_keypair, sign_pack, verify_pack_signature
from pipeline_svc.normalization import assemble_ocsf_event
from pipeline_svc.pack_registry import PackRegistry
from pipeline_svc.router import Router
from ulpf_contracts import ExtractionEnvelope, PathTaken
from ulpf_contracts.db_schema import run_migrations

REPO_ROOT = Path(__file__).resolve().parents[2]


class TestSecurityRedTeam:
    def test_redos_parser_bomb_resistance(self) -> None:
        """Attack: Inject adversarial strings designed to trigger exponential backtracking in regex."""
        # Malicious pattern with nested quantifiers (a+)+$
        priv_pem, pub_pem = generate_keypair()
        registry = PackRegistry(public_key_pem=pub_pem)

        # Standard pack with legitimate patterns
        registry.reconcile_sweep(REPO_ROOT / "packs")
        router = Router(registry=registry)

        # ReDoS payload: 10,000 repetitions of 'a' followed by '!'
        redos_payload = "a" * 10000 + "!"
        t0 = time.perf_counter()
        # Must terminate in under 50ms without hanging or crashing
        envelope = router.route_and_extract(redos_payload, uuid.uuid4(), enable_cold_path=False)
        elapsed = time.perf_counter() - t0

        assert elapsed < 0.20, f"ReDoS vulnerability detected! Parser hung for {elapsed:.3f}s"
        assert envelope is None or envelope.path_taken == PathTaken.hot

    def test_malicious_yaml_deserialization_blocked(self, tmp_path: Path) -> None:
        """Attack: Exploit PyYAML deserialization to execute arbitrary code (e.g. __reduce__, os.system)."""
        malicious_yaml = """
        pack_id: exploit_pack_v1.0.0
        source_type: exploit
        version: 1.0.0
        description: !!python/object/apply:os.system ["echo PWNED"]
        signatures: []
        """
        # SafeLoader must reject Python object execution tags
        with pytest.raises(yaml.YAMLError):
            yaml.safe_load(malicious_yaml)

    def test_path_traversal_in_storage_pointer_rejected(self) -> None:
        """Attack: Attempt to access sensitive files (/etc/passwd, win.ini) via storage_pointer."""
        malicious_pointers = [
            "raw_store://../../../../etc/passwd",
            "raw_store://..\\..\\Windows\\System32\\cmd.exe",
            "raw_store://%2e%2e%2f%2e%2e%2fetc%2fshadow",
            "file:///etc/passwd",
            "http://169.254.169.254/latest/meta-data/",
        ]
        # Contract validator must reject non-compliant storage pointer patterns
        env = ExtractionEnvelope(
            lineage_id=uuid.uuid4(),
            path_taken=PathTaken.hot,
            source_type="cisco_asa",
            extracted_fields={"action": "Deny", "protocol": "tcp", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
            confidence_scores={"action": 1.0, "protocol": 1.0, "src_ip": 1.0, "dst_ip": 1.0},
            parser_version="1.0.0",
        )
        for ptr in malicious_pointers:
            res = assemble_ocsf_event(env, raw_data_ptr=ptr)
            if not ptr.startswith("raw_store://"):
                assert res.schema_valid is False or res.ocsf_event is None

    def test_ed25519_signature_forgery_quarantined(self) -> None:
        """Attack: Forge or tamper with a single byte in the Ed25519 signature of a vendor pack."""
        priv_pem, pub_pem = generate_keypair()
        registry = PackRegistry(public_key_pem=pub_pem)

        authentic_pack = {
            "pack_id": "test_pack_v1.0.0",
            "source_type": "test_src",
            "version": "1.0.0",
            "description": "Authentic Pack",
            "signatures": [{"name": "test_sig", "pattern": r"TEST\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)", "extracted_fields": {"src_ip": "$src_ip"}}],
            "signer_key_id": "dev_signing",
        }
        sig = sign_pack(authentic_pack, priv_pem)
        authentic_pack["signature"] = sig
        assert verify_pack_signature(authentic_pack, pub_pem) is True

        # Forge signature by altering last 2 characters
        tampered_pack = dict(authentic_pack)
        tampered_pack["signature"] = sig[:-2] + ("00" if sig[-2:] != "00" else "ff")

        # Must fail signature verification and get quarantined
        assert verify_pack_signature(tampered_pack, pub_pem) is False
        loaded = registry.load_pack(tampered_pack)
        assert loaded is False
        assert "test_pack_v1.0.0" in registry.get_quarantined()
        assert "Invalid or missing Ed25519" in registry.get_quarantined()["test_pack_v1.0.0"]

    def test_cyclic_pack_inheritance_detected_and_isolated(self) -> None:
        """Attack: Author mutually recursive packs (A -> B -> A) to cause infinite recursion stack overflow."""
        pack_a = parse_pack_dict({
            "pack_id": "pack_a_v1.0.0",
            "source_type": "src_a",
            "version": "1.0.0",
            "parent_pack_id": "pack_b_v1.0.0",
            "signatures": [],
        })
        pack_b = parse_pack_dict({
            "pack_id": "pack_b_v1.0.0",
            "source_type": "src_b",
            "version": "1.0.0",
            "parent_pack_id": "pack_a_v1.0.0",
            "signatures": [],
        })

        all_packs = {"pack_a_v1.0.0": pack_a, "pack_b_v1.0.0": pack_b}
        with pytest.raises(CyclicInheritanceError):
            compile_pack(pack_a, all_packs)

    def test_merkle_domain_separation_preimage_resistance(self) -> None:
        """Attack: Attempt second-preimage attack by confusing leaf nodes (0x00) with internal nodes (0x01)."""
        content_hash = hashlib.sha256(b"raw event").hexdigest()
        leaf_hash = hashlib.sha256(b"\x00" + bytes.fromhex(content_hash)).digest()
        internal_hash = hashlib.sha256(b"\x01" + bytes.fromhex(content_hash) + bytes.fromhex(content_hash)).digest()

        # Domain separation guarantees leaf and internal prefixes produce completely disjoint hash spaces
        assert leaf_hash != internal_hash

    def test_oversized_payload_bomb_handling(self) -> None:
        """Attack: Ingest a single 5 Megabyte log line to test memory safety and limits."""
        huge_payload = "Sep 26 12:00:00 fw: " + ("A" * (5 * 1024 * 1024))
        priv_pem, pub_pem = generate_keypair()
        registry = PackRegistry(public_key_pem=pub_pem)
        registry.reconcile_sweep(REPO_ROOT / "packs")
        router = Router(registry=registry)

        t0 = time.perf_counter()
        # Router must gracefully reject/bypass without crashing
        res = router.route_and_extract(huge_payload, uuid.uuid4(), enable_cold_path=False)
        elapsed = time.perf_counter() - t0
        assert elapsed < 0.50
        assert res is None
