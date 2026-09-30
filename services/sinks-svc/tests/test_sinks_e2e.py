import json
from pathlib import Path
from typing import Any

import pandas as pd

from sinks_svc.parquet import ParquetLakeWriter
from sinks_svc.service import SinksService
from sinks_svc.siem import SiemSink


def sample_ocsf_event(seq: int = 1) -> dict[str, Any]:
    return {
        "activity_id": 5,
        "activity_name": "Refuse",
        "category_uid": 4,
        "class_uid": 4001,
        "class_name": "Network Activity",
        "severity_id": 4,
        "time": 1790328764123 + seq * 1000,
        "src_endpoint": {"ip": f"10.1.1.{seq}", "port": 40000 + seq},
        "dst_endpoint": {"ip": "8.8.8.8", "port": 443},
        "connection_info": {"protocol_num": 6, "protocol_name": "tcp"},
        "metadata": {
            "version": "1.2.0",
            "uid": f"11111111-0000-4000-a000-{seq:012d}",
            "product": {"vendor_name": "Cisco", "name": "ASA Firewall"},
        },
        "raw_data": f"raw_store://chunk_20260926_01/offset_{seq}",
        "_confidence": {"src_endpoint.ip": 1.0, "activity_id": 0.95},
        "_lineage_id": f"11111111-0000-4000-a000-{seq:012d}",
    }


def test_m5_acceptance_same_event_in_siem_and_parquet(tmp_path: Path) -> None:
    """M5 Acceptance Criterion 1 & 2: Same event in SIEM stand-in and Parquet; pandas reads with 0 preprocessing."""
    svc = SinksService(base_dir=tmp_path)
    event = sample_ocsf_event(seq=1)

    svc.publish_event(event)
    processed = svc.process_all_pending()
    assert processed["siem-streaming"] == 1
    assert processed["lake-batch"] == 1

    # Check SIEM stand-in JSONL
    siem_jsonl = tmp_path / "sinks" / "siem" / "events.jsonl"
    assert siem_jsonl.exists()
    siem_data = json.loads(siem_jsonl.read_text(encoding="utf-8").strip())
    assert siem_data["_lineage_id"] == "11111111-0000-4000-a000-000000000001"

    # Check SIEM CEF
    siem_cef = tmp_path / "sinks" / "siem" / "events.cef"
    assert siem_cef.exists()
    assert "src=10.1.1.1" in siem_cef.read_text(encoding="utf-8")

    # Check Parquet via pandas (zero preprocessing)
    lake_files = list((tmp_path / "lake" / "ocsf_events").rglob("*.parquet"))
    assert len(lake_files) == 1
    df = pd.read_parquet(lake_files[0])
    assert len(df) == 1
    assert df["_lineage_id"].iloc[0] == "11111111-0000-4000-a000-000000000001"
    assert df["_confidence"].iloc[0]["src_endpoint.ip"] == 1.0


def test_m5_acceptance_blocking_siem_does_not_affect_lake_and_siem_catches_up_in_order(tmp_path: Path) -> None:
    """
    M5 Acceptance Criterion 3:
    Killing/blocking the SIEM sink causes zero measurable impact on ingestion
    or the data lake writer, and the SIEM sink catches up in order once restored.
    """
    siem_sink = SiemSink(output_dir=tmp_path / "sinks" / "siem")
    lake_writer = ParquetLakeWriter(lake_root=tmp_path / "lake" / "ocsf_events")
    svc = SinksService(
        siem_sink=siem_sink,
        lake_writer=lake_writer,
        base_dir=tmp_path,
    )

    # 1. BLOCK THE SIEM SINK
    siem_sink.is_blocked = True

    # 2. Ingest 10 events while SIEM is down
    for i in range(1, 11):
        svc.publish_event(sample_ocsf_event(seq=i))

    # 3. Process batches: Lake must succeed completely; SIEM fails/blocks gracefully
    lake_count = svc.process_lake_batch(max_count=20)
    assert lake_count == 10, "Lake writer must process all 10 events while SIEM is blocked"

    siem_count = svc.process_siem_batch(max_count=20)
    assert siem_count == 0, "SIEM must process 0 events while blocked"

    # Verify Data Lake already has all 10 events
    lake_files = list((tmp_path / "lake" / "ocsf_events").rglob("*.parquet"))
    df = pd.concat([pd.read_parquet(f) for f in lake_files])
    assert len(df) == 10
    expected_lineages = [f"11111111-0000-4000-a000-{i:012d}" for i in range(1, 11)]
    assert sorted(df["_lineage_id"].tolist()) == sorted(expected_lineages)

    # 4. RESTORE THE SIEM SINK
    siem_sink.is_blocked = False

    # 5. SIEM catches up in order
    caught_up = svc.process_siem_batch(max_count=20)
    assert caught_up == 10, "SIEM sink must catch up all 10 events"

    # Verify SIEM has all 10 in exact sequential order
    siem_jsonl = tmp_path / "sinks" / "siem" / "events.jsonl"
    lines = [json.loads(line) for line in siem_jsonl.read_text(encoding="utf-8").strip().splitlines()]
    assert len(lines) == 10
    assert [line["_lineage_id"] for line in lines] == expected_lineages
