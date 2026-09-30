import uuid
from pathlib import Path
from typing import Any

import pytest
import yaml
from ulpf_contracts import ExtractionEnvelope
from ulpf_contracts.generated.extraction_envelope_schema import PathTaken

from pipeline_svc.db import SqlitePipelineRepository
from pipeline_svc.normalization import (
    canonicalize_activity,
    canonicalize_ip,
    canonicalize_port,
    canonicalize_protocol,
    canonicalize_timestamp,
    normalize_and_record,
)
from pipeline_svc.pack_registry import PackRegistry
from pipeline_svc.router import Router

REPO_ROOT = Path(__file__).resolve().parents[3]
PUB_KEY = (REPO_ROOT / "keys" / "dev_signing.pub").read_bytes()
BASE_PACK = REPO_ROOT / "packs" / "base" / "base_network.yaml"
ASA_PACK = REPO_ROOT / "packs" / "vendors" / "cisco_asa_v1.3.0.yaml"


class MockEventBus:
    def __init__(self) -> None:
        self.published: list[tuple[str, dict[str, Any]]] = []

    def publish(self, topic: str, message: dict[str, Any]) -> None:
        self.published.append((topic, message))


def test_ip_canonicalizer_ipv4_zero_stripping_and_ipv6_equivalence() -> None:
    # IPv4 zero-stripping
    assert canonicalize_ip("192.168.001.001") == "192.168.1.1"
    assert canonicalize_ip("010.000.000.001") == "10.0.0.1"
    assert canonicalize_ip("10.1.1.50") == "10.1.1.50"
    assert canonicalize_ip("  172.016.031.001  ") == "172.16.31.1"

    # Invalid IPv4
    assert canonicalize_ip("999.999.999.999") is None
    assert canonicalize_ip("192.168.1.300") is None
    assert canonicalize_ip("not_an_ip") is None
    assert canonicalize_ip(None) is None

    # IPv6 dual-form equivalence
    full_v6 = "2001:0DB8:0000:0000:0000:0000:0000:0001"
    compressed_v6 = "2001:db8::1"
    assert canonicalize_ip(full_v6) == "2001:db8::1"
    assert canonicalize_ip(compressed_v6) == "2001:db8::1"
    assert canonicalize_ip(full_v6) == canonicalize_ip(compressed_v6)

    # IPv6 localhost
    assert canonicalize_ip("0000:0000:0000:0000:0000:0000:0000:0001") == "::1"
    assert canonicalize_ip("::1") == "::1"


def test_port_canonicalizer_bounds_and_validation() -> None:
    # Valid boundaries
    assert canonicalize_port(0) == 0
    assert canonicalize_port(65535) == 65535
    assert canonicalize_port(80) == 80
    assert canonicalize_port("443") == 443
    assert canonicalize_port(" 514 ") == 514

    # Out of bounds / invalid
    assert canonicalize_port(-1) is None
    assert canonicalize_port(65536) is None
    assert canonicalize_port("70000") is None
    assert canonicalize_port("not_a_port") is None
    assert canonicalize_port(None) is None


def test_timestamp_canonicalizer_formats_and_epoch_ms() -> None:
    # ISO-8601 with microseconds
    iso_ms = canonicalize_timestamp("2026-09-25T09:12:44.123456Z")
    assert isinstance(iso_ms, int)
    assert iso_ms > 0

    # ISO-8601 with offset
    iso_offset = canonicalize_timestamp("2026-09-25T09:12:44.123456+00:00")
    assert iso_offset == iso_ms

    # Syslog BSD with year
    bsd_with_year = canonicalize_timestamp("Sep 25 2026 09:12:44")
    assert isinstance(bsd_with_year, int)
    assert bsd_with_year > 0

    # Syslog BSD without year
    bsd_no_year = canonicalize_timestamp("Sep 25 09:12:44")
    assert isinstance(bsd_no_year, int)
    assert bsd_no_year > 0

    # Numeric seconds & ms
    assert canonicalize_timestamp(1790327564) == 1790327564000
    assert canonicalize_timestamp(1790327564123) == 1790327564123

    # Invalid timestamp
    with pytest.raises(ValueError, match="invalid timestamp"):
        canonicalize_timestamp("invalid_date_format_xyz")

    with pytest.raises(ValueError, match="negative"):
        canonicalize_timestamp(-500)


def test_enum_canonicalizer_mappings_and_fallback_to_99() -> None:
    # Activities
    assert canonicalize_activity("deny") == (5, "Refuse")
    assert canonicalize_activity("Deny") == (5, "Refuse")
    assert canonicalize_activity("blocked") == (5, "Refuse")
    assert canonicalize_activity("allow") == (1, "Open")
    assert canonicalize_activity("permit") == (1, "Open")
    assert canonicalize_activity("close") == (2, "Close")
    assert canonicalize_activity("traffic") == (6, "Traffic")

    # Fallback to 99 Other
    assert canonicalize_activity("unknown_action_xyz") == (99, "Other")
    assert canonicalize_activity(None) == (99, "Other")

    # Protocols
    assert canonicalize_protocol("tcp") == (6, "tcp")
    assert canonicalize_protocol("TCP") == (6, "tcp")
    assert canonicalize_protocol("udp") == (17, "udp")
    assert canonicalize_protocol("icmp") == (1, "icmp")
    assert canonicalize_protocol("6") == (6, "tcp")

    # Fallback to 99
    assert canonicalize_protocol("custom_proto") == (99, "custom_proto")
    assert canonicalize_protocol(None) == (99, "unknown")


def test_cisco_asa_produces_golden_matching_ocsf_record(tmp_path: Path) -> None:
    # 1. Router extracts Cisco ASA log
    registry = PackRegistry(public_key_pem=PUB_KEY)
    assert registry.load_pack(yaml.safe_load(BASE_PACK.read_text(encoding="utf-8"))) is True
    assert registry.load_pack(yaml.safe_load(ASA_PACK.read_text(encoding="utf-8"))) is True

    router = Router(registry)
    raw_log = '<164>Sep 25 2026 09:12:44: %ASA-4-106023: Deny tcp src outside:10.1.1.50/49823 dst inside:8.8.8.8/443 by access-group "acl_outside"'
    lineage_id = uuid.uuid4()

    envelope = router.route_and_extract(raw_log, lineage_id)
    assert envelope is not None

    # 2. Normalize to OCSF 4001
    repo = SqlitePipelineRepository(str(tmp_path / "pipeline.db"))
    bus = MockEventBus()
    ext_id = repo.record_extraction(envelope)

    result, norm_id = normalize_and_record(
        envelope,
        extraction_id=ext_id,
        repo=repo,
        bus=bus,
        raw_data_ptr="raw_store://chunk_20260925_01/offset_42",
    )

    assert result.schema_valid is True
    assert result.ocsf_event is not None
    assert norm_id > 0

    event = result.ocsf_event

    # Golden OCSF 4001 Network Activity assertions
    assert event.category_uid == 4
    assert event.class_uid == 4001
    assert event.class_name == "Network Activity"
    assert event.activity_id == 5
    assert event.activity_name == "Refuse"
    assert event.severity_id == 4

    assert event.src_endpoint.ip == "10.1.1.50"
    assert event.src_endpoint.port == 49823
    assert event.dst_endpoint.ip == "8.8.8.8"
    assert event.dst_endpoint.port == 443

    assert event.connection_info is not None
    assert event.connection_info.protocol_name == "tcp"
    assert event.connection_info.protocol_num == 6

    assert event.metadata.version == "1.2.0"
    assert str(event.metadata.uid) == str(lineage_id)
    assert event.metadata.product.vendor_name == "Cisco"
    assert event.metadata.product.name == "ASA Firewall"

    # Strict invariant: metadata.uid == _lineage_id
    assert str(event.metadata.uid) == str(event.field_lineage_id)

    # Bus publication verified
    assert len(bus.published) == 1
    topic, published_msg = bus.published[0]
    assert topic == "ulpf.ocsf.events.v1"
    assert published_msg["class_uid"] == 4001
    assert published_msg["_lineage_id"] == str(lineage_id)

    # SQLite normalization_history verification
    history = repo.get_normalizations(str(lineage_id))
    assert len(history) == 1
    assert history[0]["schema_valid"] == 1
    assert history[0]["published_to_bus"] == 1
    assert history[0]["ocsf_class_uid"] == 4001


def test_invalid_timestamp_is_recorded_as_schema_valid_false_and_never_published(tmp_path: Path) -> None:
    lineage_id = uuid.uuid4()
    bad_fields = {
        "action": "Deny",
        "protocol": "tcp",
        "src_ip": "10.1.1.1",
        "src_port": "80",
        "dst_ip": "10.2.2.2",
        "dst_port": "443",
        "timestamp": "not_a_valid_date_time",
    }
    conf = {k: 1.0 for k in bad_fields}

    envelope = ExtractionEnvelope(
        lineage_id=lineage_id,
        path_taken=PathTaken.hot,
        source_type="cisco_asa",
        parser_version="1.3.0",
        extracted_fields=bad_fields,
        confidence_scores=conf,
    )

    repo = SqlitePipelineRepository(str(tmp_path / "pipeline.db"))
    bus = MockEventBus()

    result, _ = normalize_and_record(
        envelope,
        extraction_id=1,
        repo=repo,
        bus=bus,
    )

    # Schema invalid
    assert result.schema_valid is False
    assert result.ocsf_event is None
    assert result.validation_errors is not None
    assert any("timestamp" in err.lower() for err in result.validation_errors)

    # NEVER published to bus
    assert len(bus.published) == 0

    # Recorded to SQLite with schema_valid=0 and published_to_bus=0
    history = repo.get_normalizations(str(lineage_id))
    assert len(history) == 1
    assert history[0]["schema_valid"] == 0
    assert history[0]["published_to_bus"] == 0
    assert history[0]["validation_errors"] is not None
