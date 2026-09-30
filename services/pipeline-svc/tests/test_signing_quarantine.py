import copy
from pathlib import Path

from pipeline_svc.crypto import sign_pack, verify_pack_signature
from pipeline_svc.pack_registry import PackRegistry

REPO_ROOT = Path(__file__).resolve().parents[3]
PRIV_KEY = (REPO_ROOT / "keys" / "dev_signing.key").read_bytes()
PUB_KEY = (REPO_ROOT / "keys" / "dev_signing.pub").read_bytes()
EMPTY_FIELDS: dict[str, str] = {}


def test_unsigned_pack_is_quarantined_and_never_loaded() -> None:
    registry = PackRegistry(public_key_pem=PUB_KEY)

    unsigned_pack = {
        "pack_id": "unsigned_pack_v1",
        "source_type": "unsigned",
        "version": "1.0.0",
        "signatures": [{"name": "s1", "pattern": "test", "extracted_fields": EMPTY_FIELDS}],
    }

    loaded = registry.load_pack(unsigned_pack)
    assert loaded is False
    assert "unsigned_pack_v1" in registry.get_quarantined()
    assert "unsigned_pack_v1" not in registry.snapshot.packs


def test_tampered_pack_is_quarantined() -> None:
    registry = PackRegistry(public_key_pem=PUB_KEY)

    pack = {
        "pack_id": "legit_pack_v1",
        "source_type": "legit",
        "version": "1.0.0",
        "signatures": [{"name": "s1", "pattern": "legit pattern", "extracted_fields": EMPTY_FIELDS}],
    }
    pack["signature"] = sign_pack(pack, PRIV_KEY)

    assert registry.load_pack(copy.deepcopy(pack)) is True
    assert "legit_pack_v1" in registry.snapshot.packs

    tampered = copy.deepcopy(pack)
    tampered["signatures"][0]["pattern"] = "tampered malicious pattern"

    assert verify_pack_signature(tampered, PUB_KEY) is False

    registry_fresh = PackRegistry(public_key_pem=PUB_KEY)
    assert registry_fresh.load_pack(tampered) is False
    assert "legit_pack_v1" in registry_fresh.get_quarantined()
    assert "legit_pack_v1" not in registry_fresh.snapshot.packs
