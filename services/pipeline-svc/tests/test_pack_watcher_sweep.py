import shutil
from pathlib import Path

from pipeline_svc.pack_registry import PackRegistry
from pipeline_svc.router import Router

REPO_ROOT = Path(__file__).resolve().parents[3]
PUB_KEY = (REPO_ROOT / "keys" / "dev_signing.pub").read_bytes()
PACKS_DIR = REPO_ROOT / "packs"


def test_reconcile_sweep_loads_shipped_packs() -> None:
    registry = PackRegistry(public_key_pem=PUB_KEY)
    results = registry.reconcile_sweep(PACKS_DIR)

    assert "base_network_v1.0.0" in results
    assert results["base_network_v1.0.0"] is True
    assert "cisco_asa_v1.3.0" in results
    assert results["cisco_asa_v1.3.0"] is True

    snapshot = registry.snapshot
    assert "base_network_v1.0.0" in snapshot.packs
    assert "cisco_asa_v1.3.0" in snapshot.packs
    assert "cisco_asa" in snapshot.source_type_to_pack

    router = Router(registry)
    log = '<164>Sep 25 2026 09:12:44: %ASA-4-106023: Deny tcp src outside:192.168.1.1/50000 dst inside:10.0.0.1/80 by access-group "fw_rule"'
    env = router.route_and_extract(log, "00000000-0000-4000-8000-000000000001")
    assert env is not None
    assert env.extracted_fields["action"] == "Deny"
    assert env.extracted_fields["src_ip"] == "192.168.1.1"


def test_reconcile_sweep_quarantines_unsigned_files(tmp_path: Path) -> None:
    shutil.copytree(PACKS_DIR, tmp_path / "packs")

    bad_pack = tmp_path / "packs" / "vendors" / "unsigned_bad.yaml"
    bad_pack.write_text("pack_id: unsigned_bad\nsource_type: bad\nversion: 1.0.0\nsignatures: []", encoding="utf-8")

    registry = PackRegistry(public_key_pem=PUB_KEY)
    results = registry.reconcile_sweep(tmp_path / "packs")

    assert results["unsigned_bad"] is False
    assert "unsigned_bad" in registry.get_quarantined()
    assert "unsigned_bad" not in registry.snapshot.packs

    assert results["cisco_asa_v1.3.0"] is True
    assert "cisco_asa_v1.3.0" in registry.snapshot.packs
