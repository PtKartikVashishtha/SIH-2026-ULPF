"""
Performance & Latency Benchmark Runner for ULPF.

Measures:
1. Ingestion Content-Sealing (SHA-256 hashing & metadata envelope overhead)
2. Hot-Path Pattern Matching across 11 perimeter security vendors
3. OCSF 4001 Normalization Engine (IP/port/timestamp/activity canonicalization)
4. Merkle Tree Root Computation (Deterministic leaf ordering & spec padding)
5. End-to-End Full Pipeline (Ingest -> Extract -> Normalize -> Merkle Commit)

Supports:
- Parameterized scale: --scale 1k | 5k | 10k | 50k | 100k | <int>
- Multi-vendor mixed traffic benchmarking
- Latency percentiles (p50, p90, p99 in microseconds)
- Throughput in events/sec (EPS) and throughput in MB/sec
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "packages" / "contracts" / "python"))
sys.path.insert(0, str(REPO_ROOT / "services" / "pipeline-svc" / "src"))

from pipeline_svc.normalization import assemble_ocsf_event
from pipeline_svc.pack_registry import PackRegistry
from pipeline_svc.router import Router
from ulpf_contracts import ExtractionEnvelope, PathTaken

VENDOR_SAMPLES: dict[str, str] = {
    "cisco_asa": (
        '<164>Sep 26 2026 12:00:00: %ASA-4-106023: Deny tcp src outside:192.168.1.100/49823 '
        'dst inside:10.0.0.50/443 by access-group "acl_outside"'
    ),
    "fortinet_fortigate": (
        'date=2026-09-26 time=12:00:00 devname="FGT60D" devid="FGT60D123456" type="traffic" '
        'subtype="forward" level="notice" srcip=192.168.1.105 srcport=54321 dstip=10.0.0.80 '
        'dstport=80 proto=6 action="deny" policyid=1'
    ),
    "paloalto_panos": (
        'traffic,standard,1,2026/09/26 12:00:00 192.168.1.200:51234 -> 10.0.0.90:443 proto=tcp action=deny'
    ),
    "checkpoint_fw": (
        'Sep 26 12:00:00 cp-gateway CheckPoint: [action:"Drop"; proto:"tcp"; src:"192.168.2.50"; '
        'dst:"10.1.1.10"; sport:"41234"; dport:"22"; rule:"DropSSH";]'
    ),
    "juniper_srx": (
        'RT_FLOW: RT_FLOW_SESSION_CREATE: session created 192.168.3.10/61234->10.2.2.20/8080 '
        'None/None 6 basic-traffic zone-trust zone-untrust'
    ),
    "suricata_ids": (
        '[**] [1:2001219:19] ET SCAN Potential SSH Scan [**] [Priority: 2] {TCP} 192.168.4.15:48123 -> 10.3.3.30:22'
    ),
    "zeek_conn": (
        '1727352000.123456 C9yZ1234567 192.168.5.25 55432 8.8.8.8 53 udp dns 0.05 45 120 S0'
    ),
    "linux_iptables": (
        '[UFW_BLOCK]: IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.6.40 DST=10.4.4.40 '
        'LEN=60 PROTO=TCP SPT=49123 DPT=23'
    ),
    "cef_perimeter": (
        'CEF:0|VendorX|FWGateway|1.0|100|PacketDropped|Medium|src=192.168.7.60 dst=10.5.5.50 '
        'spt=38123 dpt=443 proto=tcp act=deny'
    ),
    "leef_perimeter": (
        'LEEF:2.0|IBM|QRadarFW|7.3.0|SessionDrop|src=192.168.8.70|dst=10.6.6.60|srcPort=39123|'
        'dstPort=80|proto=tcp|action=drop'
    ),
    "syslog_rfc5424": (
        '<134>1 2026-09-26T12:00:00.000Z myfirewall.corp edge-gw 1234 msg-01 - DENY TCP '
        'src=192.168.9.80:44123 dst=10.7.7.70:80'
    ),
}


def parse_scale(val: str) -> int:
    val = val.strip().lower()
    if val.endswith("k"):
        return int(float(val[:-1]) * 1000)
    if val.endswith("m"):
        return int(float(val[:-1]) * 1_000_000)
    return int(val)


def benchmark_ingestion_seal(iterations: int = 5000, sample_bytes: bytes | None = None) -> dict[str, float]:
    if sample_bytes is None:
        sample_bytes = VENDOR_SAMPLES["cisco_asa"].encode("utf-8")
    latencies: list[float] = []
    t0 = time.perf_counter()
    for _ in range(iterations):
        s0 = time.perf_counter_ns()
        _ = uuid.uuid4()
        _ = hashlib.sha256(sample_bytes).hexdigest()
        latencies.append((time.perf_counter_ns() - s0) / 1000.0)
    total_time = time.perf_counter() - t0

    latencies.sort()
    mb_processed = (len(sample_bytes) * iterations) / (1024 * 1024)
    return {
        "throughput_eps": iterations / total_time,
        "throughput_mb_s": mb_processed / total_time,
        "p50_us": latencies[int(iterations * 0.50)],
        "p90_us": latencies[int(iterations * 0.90)],
        "p99_us": latencies[int(iterations * 0.99)],
    }


def benchmark_hotpath_router(
    router: Router | None = None,
    iterations: int = 5000,
    samples: list[str] | None = None,
) -> dict[str, float]:
    if router is None:
        pub_key = (REPO_ROOT / "keys" / "dev_signing.pub").read_bytes()
        registry = PackRegistry(public_key_pem=pub_key)
        registry.reconcile_sweep(REPO_ROOT / "packs")
        router = Router(registry)
    if samples is None:
        samples = list(VENDOR_SAMPLES.values())

    uids = [uuid.uuid4() for _ in range(iterations)]
    latencies: list[float] = []
    sample_len = len(samples)

    t0 = time.perf_counter()
    for i in range(iterations):
        raw = samples[i % sample_len]
        s0 = time.perf_counter_ns()
        _ = router.route_and_extract(raw, uids[i])
        latencies.append((time.perf_counter_ns() - s0) / 1000.0)
    total_time = time.perf_counter() - t0

    latencies.sort()
    return {
        "throughput_eps": iterations / total_time,
        "p50_us": latencies[int(iterations * 0.50)],
        "p90_us": latencies[int(iterations * 0.90)],
        "p99_us": latencies[int(iterations * 0.99)],
    }


def benchmark_normalization(iterations: int) -> dict[str, float]:
    env = ExtractionEnvelope(
        lineage_id=uuid.uuid4(),
        source_type="cisco_asa",
        parser_version="1.3.0",
        extracted_fields={
            "action": "Deny",
            "protocol": "tcp",
            "src_ip": "10.1.1.50",
            "src_port": "49823",
            "dst_ip": "8.8.8.8",
            "dst_port": "443",
        },
        confidence_scores={
            "action": 1.0,
            "protocol": 1.0,
            "src_ip": 1.0,
            "src_port": 1.0,
            "dst_ip": 1.0,
            "dst_port": 1.0,
        },
        path_taken=PathTaken.hot,
    )

    latencies: list[float] = []
    t0 = time.perf_counter()
    for _ in range(iterations):
        s0 = time.perf_counter_ns()
        _ = assemble_ocsf_event(env)
        latencies.append((time.perf_counter_ns() - s0) / 1000.0)
    total_time = time.perf_counter() - t0

    latencies.sort()
    return {
        "throughput_eps": iterations / total_time,
        "p50_us": latencies[int(iterations * 0.50)],
        "p90_us": latencies[int(iterations * 0.90)],
        "p99_us": latencies[int(iterations * 0.99)],
    }


def benchmark_merkle_tree(iterations: int = 500, chunk_size: int = 100) -> dict[str, float]:
    leaf_hashes = [hashlib.sha256(f"leaf_{i}".encode()).digest() for i in range(chunk_size)]

    latencies: list[float] = []
    t0 = time.perf_counter()
    for _ in range(iterations):
        s0 = time.perf_counter_ns()
        curr = sorted(leaf_hashes)
        while len(curr) > 1:
            nxt: list[bytes] = []
            for j in range(0, len(curr), 2):
                l = curr[j]
                r = curr[j + 1] if j + 1 < len(curr) else l
                h = hashlib.sha256(b"\x01" + l + r).digest()
                nxt.append(h)
            curr = nxt
        latencies.append((time.perf_counter_ns() - s0) / 1000.0)
    total_time = time.perf_counter() - t0

    latencies.sort()
    return {
        "trees_per_sec": iterations / total_time,
        "equivalent_eps": (iterations * chunk_size) / total_time,
        "p50_us": latencies[int(iterations * 0.50)],
        "p90_us": latencies[int(iterations * 0.90)],
        "p99_us": latencies[int(iterations * 0.99)],
    }


def benchmark_end_to_end_pipeline(router: Router, iterations: int, samples: list[str]) -> dict[str, float]:
    latencies: list[float] = []
    sample_len = len(samples)
    uids = [uuid.uuid4() for _ in range(iterations)]

    t0 = time.perf_counter()
    for i in range(iterations):
        raw = samples[i % sample_len]
        s0 = time.perf_counter_ns()
        # Stage 1: Ingestion seal
        raw_bytes = raw.encode("utf-8")
        _ = hashlib.sha256(raw_bytes).hexdigest()
        # Stage 2: Hot path routing & extraction
        env = router.route_and_extract(raw, uids[i])
        # Stage 3: OCSF 4001 Normalization
        ocsf_obj = assemble_ocsf_event(env)
        # Stage 4: Merkle leaf domain hash
        _ = hashlib.sha256(b"\x00" + json.dumps(ocsf_obj.raw_dict, sort_keys=True).encode("utf-8")).digest()
        latencies.append((time.perf_counter_ns() - s0) / 1000.0)
    total_time = time.perf_counter() - t0

    latencies.sort()
    return {
        "throughput_eps": iterations / total_time,
        "p50_us": latencies[int(iterations * 0.50)],
        "p90_us": latencies[int(iterations * 0.90)],
        "p99_us": latencies[int(iterations * 0.99)],
    }


def get_memory_rss_mb() -> float:
    try:
        import psutil
        return psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)
    except Exception:
        return 0.0


def main() -> None:
    parser = argparse.ArgumentParser(description="ULPF Production Benchmark Suite")
    parser.add_argument(
        "--scale",
        default="10k",
        help="Number of iterations to benchmark (e.g., 1k, 5k, 10k, 50k, 100k, default: 10k)",
    )
    parser.add_argument(
        "--out",
        default=str(REPO_ROOT / "benchmark_results.json"),
        help="Output path for benchmark results JSON",
    )
    args = parser.parse_args()

    scale = parse_scale(args.scale)
    tree_iterations = max(100, scale // 50)

    print("=" * 68)
    print(f"  ULPF BENCHMARK SUITE (Scale: {scale:,} iterations)")
    print("=" * 68)

    pub_key = (REPO_ROOT / "keys" / "dev_signing.pub").read_bytes()
    registry = PackRegistry(public_key_pem=pub_key)
    registry.reconcile_sweep(REPO_ROOT / "packs")
    router = Router(registry)

    all_samples = list(VENDOR_SAMPLES.values())
    cisco_bytes = VENDOR_SAMPLES["cisco_asa"].encode("utf-8")

    mem_start = get_memory_rss_mb()

    # 1. Ingestion Content-Seal
    print(f"\n[1/5] Ingestion Content-Seal (SHA-256) [{scale:,} events]...")
    res_seal = benchmark_ingestion_seal(scale, cisco_bytes)
    print(f"      Throughput: {res_seal['throughput_eps']:,.0f} eps ({res_seal['throughput_mb_s']:.2f} MB/s)")
    print(f"      Latency:    p50={res_seal['p50_us']:.2f} us | p90={res_seal['p90_us']:.2f} us | p99={res_seal['p99_us']:.2f} us")

    # 2. Hot-Path Router across 11 Vendors
    print(f"\n[2/5] Hot-Path Regex Router (11 Mixed Perimeter Vendors) [{scale:,} events]...")
    res_router = benchmark_hotpath_router(router, scale, all_samples)
    print(f"      Throughput: {res_router['throughput_eps']:,.0f} eps")
    print(f"      Latency:    p50={res_router['p50_us']:.2f} us | p90={res_router['p90_us']:.2f} us | p99={res_router['p99_us']:.2f} us")

    # 3. OCSF Normalization Engine
    print(f"\n[3/5] OCSF 4001 Normalization Engine [{scale:,} events]...")
    res_norm = benchmark_normalization(scale)
    print(f"      Throughput: {res_norm['throughput_eps']:,.0f} eps")
    print(f"      Latency:    p50={res_norm['p50_us']:.2f} us | p90={res_norm['p90_us']:.2f} us | p99={res_norm['p99_us']:.2f} us")

    # 4. Merkle Tree Root Computation
    print(f"\n[4/5] Merkle Tree Builder ({tree_iterations:,} chunks x 100 leaves = {tree_iterations * 100:,} leaves)...")
    res_merkle = benchmark_merkle_tree(tree_iterations, 100)
    print(f"      Tree Rate:  {res_merkle['trees_per_sec']:,.0f} chunks/sec (equiv {res_merkle['equivalent_eps']:,.0f} leaves/sec)")
    print(f"      Latency:    p50={res_merkle['p50_us']:.2f} us | p90={res_merkle['p90_us']:.2f} us | p99={res_merkle['p99_us']:.2f} us")

    # 5. Full End-to-End Pipeline
    print(f"\n[5/5] Full End-to-End Pipeline (Ingest -> Extract -> Normalize -> Merkle) [{scale:,} events]...")
    res_e2e = benchmark_end_to_end_pipeline(router, scale, all_samples)
    print(f"      Throughput: {res_e2e['throughput_eps']:,.0f} eps")
    print(f"      Latency:    p50={res_e2e['p50_us']:.2f} us | p90={res_e2e['p90_us']:.2f} us | p99={res_e2e['p99_us']:.2f} us")

    mem_end = get_memory_rss_mb()

    # Per-Vendor Breakdown
    vendor_breakdown: dict[str, dict[str, float]] = {}
    print("\n--- Per-Vendor Hot-Path Router Throughput ---")
    single_vendor_iterations = min(scale, 2000)
    for vname, vsample in VENDOR_SAMPLES.items():
        v_res = benchmark_hotpath_router(router, single_vendor_iterations, [vsample])
        vendor_breakdown[vname] = v_res
        print(f"  {vname:<22} : {v_res['throughput_eps']:>8,.0f} eps (p50: {v_res['p50_us']:.2f} us)")

    summary = {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scale_configured": scale,
        "memory_rss_mb_start": mem_start,
        "memory_rss_mb_end": mem_end,
        "ingestion_seal": res_seal,
        "hotpath_router_mixed": res_router,
        "normalization": res_norm,
        "merkle_tree": res_merkle,
        "end_to_end_pipeline": res_e2e,
        "per_vendor_breakdown": vendor_breakdown,
    }

    out_file = Path(args.out)
    out_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("\n" + "=" * 68)
    print(f"[OK] Full benchmark suite completed. Results persisted to: {out_file.name}")
    print("=" * 68)


if __name__ == "__main__":
    main()
