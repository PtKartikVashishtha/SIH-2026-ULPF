import json
from pathlib import Path
from typing import Any

from sinks_svc.siem import SiemSink


def sample_ocsf_event() -> dict[str, Any]:
    return {
        "activity_id": 5,
        "activity_name": "Refuse",
        "category_uid": 4,
        "class_uid": 4001,
        "class_name": "Network Activity",
        "severity_id": 4,
        "time": 1790328764123,
        "src_endpoint": {"ip": "10.1.1.50", "port": 49823},
        "dst_endpoint": {"ip": "8.8.8.8", "port": 443},
        "connection_info": {"protocol_num": 6, "protocol_name": "tcp"},
        "metadata": {
            "version": "1.2.0",
            "uid": "11111111-0000-4000-a000-000000000001",
            "product": {"vendor_name": "Cisco", "name": "ASA Firewall"},
        },
        "raw_data": "raw_store://chunk_20260926_01/offset_42",
        "_confidence": {"src_endpoint.ip": 1.0, "activity_id": 0.95},
        "_lineage_id": "11111111-0000-4000-a000-000000000001",
    }


def test_siem_sink_writes_valid_jsonl_and_cef(tmp_path: Path) -> None:
    sink = SiemSink(output_dir=tmp_path / "siem")
    event = sample_ocsf_event()

    sink.write_event(event)

    # Check JSONL
    assert sink.jsonl_path.exists()
    lines = sink.jsonl_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    loaded = json.loads(lines[0])
    assert loaded["activity_name"] == "Refuse"
    assert loaded["_lineage_id"] == "11111111-0000-4000-a000-000000000001"

    # Check CEF
    assert sink.cef_path.exists()
    cef_lines = sink.cef_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(cef_lines) == 1
    cef = cef_lines[0]
    assert cef.startswith("CEF:0|Cisco|ASA Firewall|1.2.0|4001:5|Refuse|4|")
    assert "src=10.1.1.50" in cef
    assert "spt=49823" in cef
    assert "dst=8.8.8.8" in cef
    assert "dpt=443" in cef
    assert "proto=tcp" in cef
    assert "externalId=11111111-0000-4000-a000-000000000001" in cef
    assert "rt=1790328764123" in cef
