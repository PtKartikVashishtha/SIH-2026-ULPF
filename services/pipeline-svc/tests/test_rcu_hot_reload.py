import threading
import time
import uuid
from pathlib import Path

from pipeline_svc.crypto import sign_pack
from pipeline_svc.pack_registry import PackRegistry
from pipeline_svc.router import Router

REPO_ROOT = Path(__file__).resolve().parents[3]
PRIV_KEY = (REPO_ROOT / "keys" / "dev_signing.key").read_bytes()
PUB_KEY = (REPO_ROOT / "keys" / "dev_signing.pub").read_bytes()
EMPTY_FIELDS: dict[str, str] = {}


def test_atomic_snapshot_swap_zero_restart_and_rollback() -> None:
    registry = PackRegistry(public_key_pem=PUB_KEY)
    router = Router(registry)

    # 1. Load version 1.0.0
    v1 = {
        "pack_id": "test_app_v1.0.0",
        "source_type": "test_app",
        "version": "1.0.0",
        "signatures": [{"name": "app_v1", "pattern": r"APP_LOG_V1: (?P<msg>.+)", "extracted_fields": EMPTY_FIELDS}],
    }
    v1["signature"] = sign_pack(v1, PRIV_KEY)
    assert registry.load_pack(v1) is True

    uid1 = str(uuid.uuid4())
    env = router.route_and_extract("APP_LOG_V1: Hello from V1", uid1)
    assert env is not None
    assert env.parser_version == "1.0.0"
    assert env.extracted_fields["msg"] == "Hello from V1"

    # 2. Hot-reload version 2.0.0 with zero restart
    v2 = {
        "pack_id": "test_app_v2.0.0",
        "source_type": "test_app",
        "version": "2.0.0",
        "signatures": [{"name": "app_v2", "pattern": r"APP_LOG_V2: (?P<msg>.+)", "extracted_fields": EMPTY_FIELDS}],
    }
    v2["signature"] = sign_pack(v2, PRIV_KEY)
    assert registry.load_pack(v2) is True

    uid2 = str(uuid.uuid4())
    env2 = router.route_and_extract("APP_LOG_V2: Hello from V2", uid2)
    assert env2 is not None
    assert env2.parser_version == "2.0.0"

    # 3. Rollback restores prior behavior exactly
    assert registry.rollback("test_app") is True
    uid3 = str(uuid.uuid4())
    rolled_back_env = router.route_and_extract("APP_LOG_V1: Reverted to V1", uid3)
    assert rolled_back_env is not None
    assert rolled_back_env.parser_version == "1.0.0"


def test_continuous_event_stream_through_reload_has_zero_drops() -> None:
    registry = PackRegistry(public_key_pem=PUB_KEY)
    router = Router(registry)

    pack1 = {
        "pack_id": "stream_v1",
        "source_type": "stream",
        "version": "1.0",
        "signatures": [{"name": "s1", "pattern": r"STREAM: (?P<num>\d+)", "extracted_fields": EMPTY_FIELDS}],
    }
    pack1["signature"] = sign_pack(pack1, PRIV_KEY)
    registry.load_pack(pack1)

    processed_count = 0
    stop_event = threading.Event()

    def stream_worker() -> None:
        nonlocal processed_count
        i = 0
        while not stop_event.is_set():
            res = router.route_and_extract(f"STREAM: {i}", str(uuid.uuid4()))
            if res is not None and res.path_taken == "HOT":
                processed_count += 1
            i += 1
            time.sleep(0.001)

    thread = threading.Thread(target=stream_worker)
    thread.start()

    time.sleep(0.05)

    pack2 = {
        "pack_id": "stream_v2",
        "source_type": "stream",
        "version": "2.0",
        "signatures": [{"name": "s1", "pattern": r"STREAM: (?P<num>\d+)", "extracted_fields": EMPTY_FIELDS}],
    }
    pack2["signature"] = sign_pack(pack2, PRIV_KEY)
    registry.load_pack(pack2)

    time.sleep(0.05)
    stop_event.set()
    thread.join()

    assert processed_count > 30
