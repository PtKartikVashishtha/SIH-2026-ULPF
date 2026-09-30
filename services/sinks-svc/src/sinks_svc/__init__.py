"""sinks-svc — C8: SIEM adapter (JSONL/syslog-CEF) + Parquet data lake writer (M5)."""

from sinks_svc.bus import BusMessage, ConsumerGroup, LocalMessageBus
from sinks_svc.parquet import ParquetLakeWriter, build_ocsf_parquet_schema
from sinks_svc.service import GROUP_LAKE, GROUP_SIEM, TOPIC_OCSF_EVENTS, SinksService
from sinks_svc.siem import SiemSink, escape_cef_extension, escape_cef_header

__all__ = [
    "BusMessage",
    "ConsumerGroup",
    "GROUP_LAKE",
    "GROUP_SIEM",
    "LocalMessageBus",
    "ParquetLakeWriter",
    "SiemSink",
    "SinksService",
    "TOPIC_OCSF_EVENTS",
    "build_ocsf_parquet_schema",
    "escape_cef_extension",
    "escape_cef_header",
]
