from pathlib import Path

import yaml

from pipeline_svc.db import SqlitePipelineRepository
from pipeline_svc.pack_registry import PackRegistry
from pipeline_svc.router import Router

REPO_ROOT = Path(__file__).resolve().parents[3]
PUB_KEY = (REPO_ROOT / "keys" / "dev_signing.pub").read_bytes()
BASE_PACK = REPO_ROOT / "packs" / "base" / "base_network.yaml"
ASA_PACK = REPO_ROOT / "packs" / "vendors" / "cisco_asa_v1.3.0.yaml"


def test_cisco_asa_fixtures_produce_correct_envelopes_at_confidence_1_0(tmp_path: Path) -> None:
    registry = PackRegistry(public_key_pem=PUB_KEY)

    assert registry.load_pack(yaml.safe_load(BASE_PACK.read_text(encoding="utf-8"))) is True
    assert registry.load_pack(yaml.safe_load(ASA_PACK.read_text(encoding="utf-8"))) is True

    router = Router(registry)
    db = SqlitePipelineRepository(str(tmp_path / "test_pipeline.db"))

    raw_log = '<164>Sep 25 2026 09:12:44: %ASA-4-106023: Deny tcp src outside:10.1.1.50/49823 dst inside:8.8.8.8/443 by access-group "acl_outside"'
    lineage_id = "11111111-2222-4000-a000-333333333333"

    envelope = router.route_and_extract(raw_log, lineage_id)

    assert envelope is not None
    assert str(envelope.lineage_id) == lineage_id
    assert envelope.path_taken == "HOT" or getattr(envelope.path_taken, "value", None) == "HOT"
    assert envelope.source_type == "cisco_asa"
    assert envelope.parser_version == "1.3.0"

    fields = envelope.extracted_fields
    assert fields["action"] == "Deny"
    assert fields["protocol"] == "tcp"
    assert fields["src_interface"] == "outside"
    assert fields["src_ip"] == "10.1.1.50"
    assert fields["src_port"] == "49823"
    assert fields["dst_interface"] == "inside"
    assert fields["dst_ip"] == "8.8.8.8"
    assert fields["dst_port"] == "443"
    assert fields["acl_name"] == "acl_outside"

    for _field_name, score in envelope.confidence_scores.items():
        assert score == 1.0

    rec_id = db.record_extraction(envelope)
    assert rec_id > 0

    history = db.get_extractions(lineage_id)
    assert len(history) == 1
    assert history[0]["path_taken"] == "HOT"
    assert history[0]["source_type"] == "cisco_asa"
