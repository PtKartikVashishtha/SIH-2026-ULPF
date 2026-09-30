"""
Sinks Service Orchestrator for ULPF (M5).

Connects the Local Message Bus (`ulpf.ocsf.events.v1`) to:
1. `siem-streaming` consumer group -> `SiemSink` (JSONL + CEF stand-in).
2. `lake-batch` consumer group -> `ParquetLakeWriter` (Date-partitioned Parquet with `_confidence` struct).

Guarantees complete backpressure isolation: failure or stoppage of the SIEM sink
does not impact data lake ingestion, and SIEM catches up in order once unblocked.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Any

from sinks_svc.bus import LocalMessageBus
from sinks_svc.parquet import ParquetLakeWriter
from sinks_svc.siem import SiemSink

logger = logging.getLogger(__name__)

TOPIC_OCSF_EVENTS = "ulpf.ocsf.events.v1"
GROUP_SIEM = "siem-streaming"
GROUP_LAKE = "lake-batch"


class SinksService:
    """Manages independent consumer groups for SIEM and Data Lake sinks."""

    def __init__(
        self,
        bus: LocalMessageBus | None = None,
        siem_sink: SiemSink | None = None,
        lake_writer: ParquetLakeWriter | None = None,
        base_dir: Path | str = "data",
    ) -> None:
        self.base_dir = Path(base_dir)
        self.bus = bus or LocalMessageBus()
        self.siem_sink = siem_sink or SiemSink(output_dir=self.base_dir / "sinks" / "siem")
        self.lake_writer = lake_writer or ParquetLakeWriter(lake_root=self.base_dir / "lake" / "ocsf_events")

        # Register consumer groups on ulpf.ocsf.events.v1
        self.siem_group = self.bus.register_consumer_group(
            group_id=GROUP_SIEM,
            topic=TOPIC_OCSF_EVENTS,
            max_queue_size=1000,
            spool_dir=self.base_dir / "spool" / GROUP_SIEM,
        )
        self.lake_group = self.bus.register_consumer_group(
            group_id=GROUP_LAKE,
            topic=TOPIC_OCSF_EVENTS,
            max_queue_size=1000,
            spool_dir=self.base_dir / "spool" / GROUP_LAKE,
        )

        self._running = False
        self._threads: list[threading.Thread] = []

    def publish_event(self, event: dict[str, Any]) -> int:
        """Publishes an OCSF event onto the message bus."""
        return self.bus.publish(TOPIC_OCSF_EVENTS, event)

    def process_siem_batch(self, max_count: int = 100) -> int:
        """Polls and writes up to max_count events to the SIEM stand-in sink."""
        messages = self.bus.poll(GROUP_SIEM, max_count=max_count)
        if not messages:
            return 0

        events = [m.payload for m in messages]
        try:
            self.siem_sink.write_batch(events)
            # Only commit offset if write succeeds
            self.bus.commit(GROUP_SIEM, messages[-1].offset)
            return len(events)
        except Exception as e:
            logger.warning("SIEM sink write failed or blocked: %s", e)
            return 0

    def process_lake_batch(self, max_count: int = 100) -> int:
        """Polls and writes up to max_count events to the Parquet data lake."""
        messages = self.bus.poll(GROUP_LAKE, max_count=max_count)
        if not messages:
            return 0

        events = [m.payload for m in messages]
        try:
            self.lake_writer.write_batch(events)
            # Only commit offset if write succeeds
            self.bus.commit(GROUP_LAKE, messages[-1].offset)
            return len(events)
        except Exception as e:
            logger.error("Data lake Parquet write failed: %s", e)
            raise

    def process_all_pending(self, max_iterations: int = 100) -> dict[str, int]:
        """Drains and processes all available messages for both sinks."""
        processed = {GROUP_SIEM: 0, GROUP_LAKE: 0}
        for _ in range(max_iterations):
            siem_n = self.process_siem_batch(max_count=100)
            lake_n = self.process_lake_batch(max_count=100)
            processed[GROUP_SIEM] += siem_n
            processed[GROUP_LAKE] += lake_n
            if siem_n == 0 and lake_n == 0:
                break
        return processed

    def start_background_workers(self, poll_interval_s: float = 0.05) -> None:
        """Starts independent worker threads for SIEM and Lake consumers."""
        self._running = True

        def siem_worker() -> None:
            while self._running:
                try:
                    count = self.process_siem_batch(max_count=100)
                    if count == 0:
                        time.sleep(poll_interval_s)
                except Exception:
                    time.sleep(poll_interval_s)

        def lake_worker() -> None:
            while self._running:
                try:
                    count = self.process_lake_batch(max_count=100)
                    if count == 0:
                        time.sleep(poll_interval_s)
                except Exception:
                    time.sleep(poll_interval_s)

        t_siem = threading.Thread(target=siem_worker, daemon=True, name="siem-worker")
        t_lake = threading.Thread(target=lake_worker, daemon=True, name="lake-worker")
        t_siem.start()
        t_lake.start()
        self._threads = [t_siem, t_lake]

    def stop_background_workers(self) -> None:
        self._running = False
        for t in self._threads:
            t.join(timeout=1.0)
        self._threads.clear()
