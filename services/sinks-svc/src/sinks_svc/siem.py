"""
SIEM Stand-In Sink for ULPF Sinks Service (M5).

Outputs OCSF normalized events in two standard formats:
1. JSONL: Newline-delimited JSON log file.
2. Syslog / CEF (Common Event Format): Standard SIEM ingestion format.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any


def escape_cef_header(value: str) -> str:
    """Escapes pipe (|) and backslash (\\) in CEF header fields."""
    return value.replace("\\", "\\\\").replace("|", "\\|")


def escape_cef_extension(value: str) -> str:
    """Escapes backslash (\\) and equals (=) in CEF extension value fields."""
    return value.replace("\\", "\\\\").replace("=", "\\=")


class SiemSink:
    """SIEM stand-in sink supporting JSONL and Syslog/CEF output."""

    def __init__(
        self,
        output_dir: Path | str = "data/sinks/siem",
        jsonl_filename: str = "events.jsonl",
        cef_filename: str = "events.cef",
    ) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl_path = self.output_dir / jsonl_filename
        self.cef_path = self.output_dir / cef_filename
        self._lock = threading.Lock()

        # Fault injection toggles for backpressure / kill / resilience drills
        self.is_blocked: bool = False
        self.simulated_delay_s: float = 0.0
        self.events_written: int = 0

    def format_cef(self, event: dict[str, Any]) -> str:
        """
        Converts an OCSF 4001 normalized event dictionary into standard CEF syntax:
        CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
        """
        metadata = event.get("metadata") or {}
        product = metadata.get("product") or {}
        vendor = escape_cef_header(product.get("vendor_name", "ULPF"))
        prod_name = escape_cef_header(product.get("name", "OCSF Normalizer"))
        version = escape_cef_header(metadata.get("version", "1.2.0"))

        class_uid = event.get("class_uid", 4001)
        activity_id = event.get("activity_id", 0)
        event_class_id = escape_cef_header(f"{class_uid}:{activity_id}")
        name = escape_cef_header(event.get("activity_name", "Unknown Activity"))
        severity = escape_cef_header(str(event.get("severity_id", 1)))

        # Extensions
        ext_parts: list[str] = []

        src = event.get("src_endpoint") or {}
        if src.get("ip"):
            ext_parts.append(f"src={escape_cef_extension(src['ip'])}")
        if src.get("port") is not None:
            ext_parts.append(f"spt={src['port']}")

        dst = event.get("dst_endpoint") or {}
        if dst.get("ip"):
            ext_parts.append(f"dst={escape_cef_extension(dst['ip'])}")
        if dst.get("port") is not None:
            ext_parts.append(f"dpt={dst['port']}")

        conn = event.get("connection_info") or {}
        if conn.get("protocol_name"):
            ext_parts.append(f"proto={escape_cef_extension(conn['protocol_name'])}")

        lineage_id = event.get("_lineage_id") or metadata.get("uid")
        if lineage_id:
            ext_parts.append(f"externalId={escape_cef_extension(lineage_id)}")

        event_time = event.get("time")
        if event_time is not None:
            ext_parts.append(f"rt={event_time}")

        raw_data = event.get("raw_data")
        if raw_data:
            ext_parts.append(f"rawEventPointer={escape_cef_extension(raw_data)}")

        confidence = event.get("_confidence")
        if confidence and isinstance(confidence, dict):
            ext_parts.append(f"cs1Label=confidence cs1={escape_cef_extension(json.dumps(confidence))}")

        extension_str = " ".join(ext_parts)
        return f"CEF:0|{vendor}|{prod_name}|{version}|{event_class_id}|{name}|{severity}|{extension_str}"

    def write_event(self, event: dict[str, Any]) -> None:
        """Writes a single event to both JSONL and CEF stand-in files."""
        self.write_batch([event])

    def write_batch(self, events: list[dict[str, Any]]) -> int:
        """Writes a batch of events to both JSONL and CEF stand-in files."""
        if not events:
            return 0

        if self.is_blocked:
            raise RuntimeError("SIEM sink is currently blocked or offline")

        if self.simulated_delay_s > 0:
            time.sleep(self.simulated_delay_s)

        jsonl_lines = [json.dumps(ev, default=str) + "\n" for ev in events]
        cef_lines = [self.format_cef(ev) + "\n" for ev in events]

        with self._lock:
            with open(self.jsonl_path, "a", encoding="utf-8") as f_jsonl:
                f_jsonl.writelines(jsonl_lines)

            with open(self.cef_path, "a", encoding="utf-8") as f_cef:
                f_cef.writelines(cef_lines)

            self.events_written += len(events)

        return len(events)
