"""
Local Message Bus for ULPF Sinks Service (M5).

Features:
- Independent consumer-group offsets (Kafka-like semantics).
- Per-group backpressure isolation and overflow disk spooling.
- Non-blocking publisher: slow or failing consumers never stall ingestion or other sinks.
- Resilient fetch & commit semantics: uncommitted messages are never lost on consumer error.
- Strict in-order replay from memory queue and disk spool upon consumer recovery.
"""

from __future__ import annotations

import json
import threading
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class BusMessage:
    topic: str
    offset: int
    payload: dict[str, Any]


class ConsumerGroup:
    """Manages offset, memory buffer, and disk overflow spool for a single consumer group."""

    def __init__(
        self,
        group_id: str,
        topic: str,
        max_queue_size: int = 1000,
        spool_dir: Path | str | None = None,
    ) -> None:
        self.group_id = group_id
        self.topic = topic
        self.max_queue_size = max_queue_size
        self.spool_dir = Path(spool_dir or f"data/spool/{group_id}")
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        self.spool_file = self.spool_dir / "spool.jsonl"
        self.offset_file = self.spool_dir / "committed_offset.json"

        self._lock = threading.Lock()
        self.committed_offset: int = self._load_committed_offset()
        self.memory_queue: deque[BusMessage] = deque()
        self.is_blocked: bool = False
        self.total_spooled: int = 0

    def _load_committed_offset(self) -> int:
        if self.offset_file.exists():
            try:
                data = json.loads(self.offset_file.read_text(encoding="utf-8"))
                return int(data.get("offset", -1))
            except Exception:
                return -1
        return -1

    def _save_committed_offset(self, offset: int) -> None:
        self.committed_offset = offset
        temp_file = self.spool_dir / "committed_offset.tmp"
        temp_file.write_text(json.dumps({"offset": offset}), encoding="utf-8")
        temp_file.replace(self.offset_file)

    def enqueue(self, msg: BusMessage) -> None:
        with self._lock:
            has_spool = self.spool_file.exists() and self.spool_file.stat().st_size > 0
            # If in-memory buffer has reached max capacity or spool is active, append to disk spool
            if len(self.memory_queue) >= self.max_queue_size or has_spool:
                self._spool_message(msg)
            else:
                self.memory_queue.append(msg)

    def _spool_message(self, msg: BusMessage) -> None:
        with open(self.spool_file, "a", encoding="utf-8") as f:
            f.write(json.dumps({"topic": msg.topic, "offset": msg.offset, "payload": msg.payload}) + "\n")
        self.total_spooled += 1

    def poll(self, max_count: int = 100) -> list[BusMessage]:
        """
        Fetches up to max_count uncommitted messages starting strictly from committed_offset + 1.
        Messages remain in the buffer/spool until explicitly committed via commit().
        """
        with self._lock:
            if self.is_blocked:
                return []

            results: list[BusMessage] = []

            # 1. Fetch uncommitted messages from memory queue first (earliest)
            for msg in self.memory_queue:
                if msg.offset > self.committed_offset:
                    results.append(msg)
                    if len(results) >= max_count:
                        return results

            # 2. If more messages needed and spool exists, fetch from spool (later)
            if self.spool_file.exists() and self.spool_file.stat().st_size > 0:
                with open(self.spool_file, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        entry = json.loads(line)
                        offset = entry["offset"]
                        if offset > self.committed_offset and (not results or offset > results[-1].offset):
                            results.append(
                                BusMessage(
                                    topic=entry["topic"],
                                    offset=offset,
                                    payload=entry["payload"],
                                )
                            )
                            if len(results) >= max_count:
                                return results

            return results

    def commit(self, offset: int) -> None:
        """Commits offset and prunes acknowledged messages from memory and disk spool."""
        with self._lock:
            if offset <= self.committed_offset:
                return

            self._save_committed_offset(offset)

            # 1. Prune committed messages from memory queue
            while self.memory_queue and self.memory_queue[0].offset <= self.committed_offset:
                self.memory_queue.popleft()

            # 2. Prune committed messages from disk spool
            if self.spool_file.exists() and self.spool_file.stat().st_size > 0:
                remaining_lines: list[str] = []
                with open(self.spool_file, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        entry = json.loads(line)
                        if entry["offset"] > self.committed_offset:
                            remaining_lines.append(line)

                if remaining_lines:
                    temp_spool = self.spool_dir / "spool.tmp"
                    with open(temp_spool, "w", encoding="utf-8") as f:
                        for rl in remaining_lines:
                            f.write(rl + "\n")
                    temp_spool.replace(self.spool_file)
                else:
                    self.spool_file.unlink(missing_ok=True)

    def set_blocked(self, blocked: bool) -> None:
        with self._lock:
            self.is_blocked = blocked


class LocalMessageBus:
    """Local multi-topic message bus with independent consumer groups and per-group overflow spooling."""

    def __init__(self) -> None:
        self._groups_by_topic: dict[str, list[ConsumerGroup]] = {}
        self._groups_by_id: dict[str, ConsumerGroup] = {}
        self._topic_offsets: dict[str, int] = {}
        self._lock = threading.Lock()

    def register_consumer_group(
        self,
        group_id: str,
        topic: str,
        max_queue_size: int = 1000,
        spool_dir: Path | str | None = None,
    ) -> ConsumerGroup:
        with self._lock:
            if group_id in self._groups_by_id:
                return self._groups_by_id[group_id]

            group = ConsumerGroup(
                group_id=group_id,
                topic=topic,
                max_queue_size=max_queue_size,
                spool_dir=spool_dir,
            )
            self._groups_by_id[group_id] = group
            self._groups_by_topic.setdefault(topic, []).append(group)
            current_topic_offset = self._topic_offsets.get(topic, -1)
            self._topic_offsets[topic] = max(current_topic_offset, group.committed_offset)
            return group

    def publish(self, topic: str, payload: dict[str, Any]) -> int:
        """Publishes an event to a topic. Non-blocking to slow/failing consumer groups."""
        with self._lock:
            current_offset = self._topic_offsets.get(topic, -1) + 1
            self._topic_offsets[topic] = current_offset
            groups = list(self._groups_by_topic.get(topic, []))

        msg = BusMessage(topic=topic, offset=current_offset, payload=payload)
        for group in groups:
            group.enqueue(msg)

        return current_offset

    def poll(self, group_id: str, max_count: int = 100) -> list[BusMessage]:
        group = self._groups_by_id.get(group_id)
        if not group:
            raise KeyError(f"Unknown consumer group: {group_id}")
        return group.poll(max_count=max_count)

    def commit(self, group_id: str, offset: int) -> None:
        group = self._groups_by_id.get(group_id)
        if not group:
            raise KeyError(f"Unknown consumer group: {group_id}")
        group.commit(offset)

    def get_group(self, group_id: str) -> ConsumerGroup:
        if group_id not in self._groups_by_id:
            raise KeyError(f"Unknown consumer group: {group_id}")
        return self._groups_by_id[group_id]

    def get_lag(self, group_id: str) -> int:
        with self._lock:
            group = self._groups_by_id.get(group_id)
            if not group:
                return 0
            latest = self._topic_offsets.get(group.topic, -1)
            return max(0, latest - group.committed_offset)
