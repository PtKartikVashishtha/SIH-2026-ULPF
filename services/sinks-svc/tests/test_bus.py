from pathlib import Path

from sinks_svc.bus import LocalMessageBus


def test_independent_consumer_group_offsets(tmp_path: Path) -> None:
    bus = LocalMessageBus()
    group_a = bus.register_consumer_group("group-a", "test.topic", max_queue_size=10, spool_dir=tmp_path / "a")
    group_b = bus.register_consumer_group("group-b", "test.topic", max_queue_size=10, spool_dir=tmp_path / "b")

    # Publish 5 events
    for i in range(5):
        bus.publish("test.topic", {"seq": i})

    # Poll group A (read 3, commit 2)
    msgs_a = bus.poll("group-a", max_count=3)
    assert len(msgs_a) == 3
    assert [m.payload["seq"] for m in msgs_a] == [0, 1, 2]
    bus.commit("group-a", msgs_a[-1].offset)
    assert group_a.committed_offset == 2

    # Group B must still be at offset -1 and receive all 5
    assert group_b.committed_offset == -1
    msgs_b = bus.poll("group-b", max_count=5)
    assert len(msgs_b) == 5
    assert [m.payload["seq"] for m in msgs_b] == [0, 1, 2, 3, 4]


def test_overflow_disk_spooling_and_catchup(tmp_path: Path) -> None:
    bus = LocalMessageBus()
    group = bus.register_consumer_group("overflow-group", "spool.topic", max_queue_size=2, spool_dir=tmp_path / "spool")

    # Publish 6 messages (capacity is 2, so 4 should spool to disk)
    for i in range(6):
        bus.publish("spool.topic", {"index": i})

    assert group.spool_file.exists()
    assert group.total_spooled >= 4

    # Poll in batches and commit
    batch1 = bus.poll("overflow-group", max_count=3)
    assert len(batch1) == 3
    bus.commit("overflow-group", batch1[-1].offset)

    batch2 = bus.poll("overflow-group", max_count=3)
    assert len(batch2) == 3
    bus.commit("overflow-group", batch2[-1].offset)

    all_received = [m.payload["index"] for m in batch1 + batch2]
    assert all_received == [0, 1, 2, 3, 4, 5], "Events must be delivered in strict order across memory and spool"


def test_blocked_group_does_not_block_publisher_or_other_groups(tmp_path: Path) -> None:
    bus = LocalMessageBus()
    blocked_group = bus.register_consumer_group(
        "blocked-group", "multi.topic", max_queue_size=2, spool_dir=tmp_path / "blk"
    )
    bus.register_consumer_group(
        "healthy-group", "multi.topic", max_queue_size=10, spool_dir=tmp_path / "hlth"
    )

    blocked_group.set_blocked(True)

    # Publishing must not hang or fail
    for i in range(5):
        bus.publish("multi.topic", {"val": i})

    # Healthy group consumes seamlessly
    healthy_msgs = bus.poll("healthy-group", max_count=10)
    assert len(healthy_msgs) == 5
    assert [m.payload["val"] for m in healthy_msgs] == [0, 1, 2, 3, 4]

    # Blocked group returns empty while blocked
    assert bus.poll("blocked-group", max_count=10) == []

    # Unblocking allows catchup
    blocked_group.set_blocked(False)
    recovered_msgs = bus.poll("blocked-group", max_count=10)
    assert len(recovered_msgs) == 5
    assert [m.payload["val"] for m in recovered_msgs] == [0, 1, 2, 3, 4]
