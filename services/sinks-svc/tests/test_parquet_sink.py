from pathlib import Path
from typing import Any

import pandas as pd

from sinks_svc.parquet import ParquetLakeWriter


def sample_ocsf_event() -> dict[str, Any]:
    return {
        "activity_id": 5,
        "activity_name": "Refuse",
        "category_uid": 4,
        "class_uid": 4001,
        "class_name": "Network Activity",
        "severity_id": 4,
        "time": 1790328764123,  # Sep 2026
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


def test_parquet_writer_creates_partitioned_typed_file(tmp_path: Path) -> None:
    writer = ParquetLakeWriter(lake_root=tmp_path / "lake")
    event = sample_ocsf_event()

    paths = writer.write_batch([event])
    assert len(paths) == 1
    p_file = paths[0]
    assert p_file.exists()
    assert "year=2026" in str(p_file)

    # Acceptance Criterion: pandas.read_parquet works with zero preprocessing
    df = pd.read_parquet(p_file)
    assert len(df) == 1
    row = df.iloc[0]

    assert row["class_uid"] == 4001
    assert row["activity_name"] == "Refuse"
    assert row["_lineage_id"] == "11111111-0000-4000-a000-000000000001"
    assert row["src_endpoint"]["ip"] == "10.1.1.50"
    assert row["src_endpoint"]["port"] == 49823

    # Struct confidence column
    conf = row["_confidence"]
    assert isinstance(conf, dict)
    assert conf["src_endpoint.ip"] == 1.0
    assert abs(conf["activity_id"] - 0.95) < 0.001
