"""
Parquet Data Lake Writer for ULPF Sinks Service (M5).

Features:
- Strongly typed PyArrow schema matching OCSF 4001 specifications.
- Dedicated `_confidence` struct column containing per-field float confidence scores.
- Date-partitioned directory layout (`year=YYYY/month=MM/day=DD/`).
- Guaranteed seamless zero-preprocessing ingestion via `pandas.read_parquet()`.
"""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pyarrow as pa  # type: ignore[import-untyped]
import pyarrow.parquet as pq  # type: ignore[import-untyped]


def build_ocsf_parquet_schema(confidence_keys: list[str] | set[str]) -> pa.Schema:
    """Builds the strongly-typed PyArrow schema for OCSF 4001 with a `_confidence` struct column."""
    # Ensure stable field ordering for the confidence struct
    sorted_conf_keys = sorted(confidence_keys) if confidence_keys else ["overall"]
    conf_fields = [pa.field(k, pa.float32(), nullable=True) for k in sorted_conf_keys]
    confidence_struct = pa.struct(conf_fields)

    fields = [
        pa.field("activity_id", pa.int32(), nullable=True),
        pa.field("activity_name", pa.string(), nullable=True),
        pa.field("category_uid", pa.int32(), nullable=True),
        pa.field("class_uid", pa.int32(), nullable=True),
        pa.field("class_name", pa.string(), nullable=True),
        pa.field("severity_id", pa.int32(), nullable=True),
        pa.field("time", pa.int64(), nullable=True),
        pa.field(
            "src_endpoint",
            pa.struct([
                pa.field("ip", pa.string(), nullable=True),
                pa.field("port", pa.int32(), nullable=True),
            ]),
            nullable=True,
        ),
        pa.field(
            "dst_endpoint",
            pa.struct([
                pa.field("ip", pa.string(), nullable=True),
                pa.field("port", pa.int32(), nullable=True),
            ]),
            nullable=True,
        ),
        pa.field(
            "connection_info",
            pa.struct([
                pa.field("protocol_num", pa.int32(), nullable=True),
                pa.field("protocol_name", pa.string(), nullable=True),
            ]),
            nullable=True,
        ),
        pa.field(
            "metadata",
            pa.struct([
                pa.field("version", pa.string(), nullable=True),
                pa.field("uid", pa.string(), nullable=True),
                pa.field(
                    "product",
                    pa.struct([
                        pa.field("vendor_name", pa.string(), nullable=True),
                        pa.field("name", pa.string(), nullable=True),
                    ]),
                    nullable=True,
                ),
            ]),
            nullable=True,
        ),
        pa.field("raw_data", pa.string(), nullable=True),
        pa.field("_lineage_id", pa.string(), nullable=True),
        pa.field("_confidence", confidence_struct, nullable=True),
    ]

    return pa.schema(fields)


class ParquetLakeWriter:
    """Writes OCSF events to a local partitioned Parquet data lake."""

    def __init__(self, lake_root: Path | str = "data/lake/ocsf_events") -> None:
        self.lake_root = Path(lake_root)
        self.lake_root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.total_written: int = 0

    def _prepare_record(self, event: dict[str, Any], conf_keys: list[str]) -> dict[str, Any]:
        """Normalizes an OCSF event dict to match the PyArrow schema strictly."""
        metadata = event.get("metadata") or {}
        product = metadata.get("product") or {}
        src = event.get("src_endpoint") or {}
        dst = event.get("dst_endpoint") or {}
        conn = event.get("connection_info") or {}

        # Build confidence dictionary aligned with struct fields
        raw_conf = event.get("_confidence") or {}
        conf_dict: dict[str, float | None] = {}
        for k in conf_keys:
            val = raw_conf.get(k)
            conf_dict[k] = float(val) if val is not None else None

        lineage_id = event.get("_lineage_id") or metadata.get("uid")

        return {
            "activity_id": event.get("activity_id"),
            "activity_name": event.get("activity_name"),
            "category_uid": event.get("category_uid"),
            "class_uid": event.get("class_uid"),
            "class_name": event.get("class_name"),
            "severity_id": event.get("severity_id"),
            "time": event.get("time"),
            "src_endpoint": {
                "ip": src.get("ip"),
                "port": src.get("port"),
            },
            "dst_endpoint": {
                "ip": dst.get("ip"),
                "port": dst.get("port"),
            },
            "connection_info": {
                "protocol_num": conn.get("protocol_num"),
                "protocol_name": conn.get("protocol_name"),
            },
            "metadata": {
                "version": metadata.get("version"),
                "uid": str(metadata.get("uid")) if metadata.get("uid") is not None else None,
                "product": {
                    "vendor_name": product.get("vendor_name"),
                    "name": product.get("name"),
                },
            },
            "raw_data": event.get("raw_data"),
            "_lineage_id": str(lineage_id) if lineage_id else None,
            "_confidence": conf_dict,
        }

    def write_batch(self, events: list[dict[str, Any]]) -> list[Path]:
        """Writes a batch of events partitioned by date into Parquet files."""
        if not events:
            return []

        # 1. Discover all confidence keys across the batch
        conf_keys_set: set[str] = set()
        for ev in events:
            c = ev.get("_confidence")
            if isinstance(c, dict):
                conf_keys_set.update(c.keys())

        conf_keys = sorted(conf_keys_set) if conf_keys_set else ["overall"]
        schema = build_ocsf_parquet_schema(conf_keys)

        # 2. Group records by partition (year=YYYY/month=MM/day=DD)
        partitions: dict[tuple[int, int, int], list[dict[str, Any]]] = {}
        for ev in events:
            t = ev.get("time")
            if t is not None:
                try:
                    dt = datetime.fromtimestamp(t / 1000.0, tz=UTC)
                except Exception:
                    dt = datetime.now(UTC)
            else:
                dt = datetime.now(UTC)

            part_key = (dt.year, dt.month, dt.day)
            prepared = self._prepare_record(ev, conf_keys)
            partitions.setdefault(part_key, []).append(prepared)

        # 3. Write Parquet files per partition
        written_paths: list[Path] = []
        with self._lock:
            for (year, month, day), p_records in partitions.items():
                part_dir = self.lake_root / f"year={year:04d}" / f"month={month:02d}" / f"day={day:02d}"
                part_dir.mkdir(parents=True, exist_ok=True)

                batch_uuid = uuid.uuid4().hex[:12]
                file_path = part_dir / f"events_{batch_uuid}.parquet"

                table = pa.Table.from_pylist(p_records, schema=schema)
                pq.write_table(table, file_path, compression="zstd")
                written_paths.append(file_path)
                self.total_written += len(p_records)

        return written_paths
