#!/usr/bin/env python3
"""
ULPF Real-Time IoT & Network Multi-Device Live Stream Generator.
Simulates a distributed fleet of IoT sensors, industrial controllers, and network firewalls
streaming raw logs directly to the ULPF ingestion cluster in real time over UDP, TCP, or HTTP.

Demonstrates:
  1. Live real-time ingestion from multiple distinct device IP addresses.
  2. Autonomous Hot-Path vs. Cold-Path real-time classification.
  3. Dynamic Drain3 template discovery for novel IoT telemetry -> Web Review Queue.
  4. Real-time OCSF 4001 canonical normalization.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import socket
import sys
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# Enable ANSI colors on Windows
if os.name == "nt":
    os.system("")

REPO_ROOT = Path(__file__).resolve().parent.parent

# ── DEVICE SIMULATION PROFILES ───────────────────────────────────────────────

@dataclass
class DeviceProfile:
    device_id: str
    ip: str
    category: str
    expected_path: str  # "HOT" or "COLD"
    generator_func: str

DEVICE_FLEET = [
    # 1. Hot Path: Cisco ASA Edge Firewall (Known regex pack v1.3.0)
    DeviceProfile(
        device_id="cisco-asa-edge-01",
        ip="10.0.1.1",
        category="Network Firewall",
        expected_path="HOT",
        generator_func="gen_cisco_asa",
    ),
    # 2. Cold Path: Industrial Smart Power Meter (Novel telemetry)
    DeviceProfile(
        device_id="smart-meter-substation-b",
        ip="192.168.10.45",
        category="IoT Smart Meter",
        expected_path="COLD",
        generator_func="gen_smart_meter",
    ),
    # 3. Cold Path: Environmental Air Quality Monitor (Novel telemetry)
    DeviceProfile(
        device_id="env-sensor-bldg4",
        ip="192.168.30.99",
        category="IoT Environmental",
        expected_path="COLD",
        generator_func="gen_air_quality",
    ),
    # 4. Cold Path: Factory Floor Vibration Sensor (Novel industrial sensor)
    DeviceProfile(
        device_id="vibration-pump-12",
        ip="192.168.20.12",
        category="Industrial SCADA",
        expected_path="COLD",
        generator_func="gen_vibration",
    ),
    # 5. Hot Path: Edge Gateway Linux Syslog
    DeviceProfile(
        device_id="edge-gw-03",
        ip="172.16.0.5",
        category="Linux Gateway",
        expected_path="HOT",
        generator_func="gen_linux_syslog",
    ),
]


def gen_cisco_asa(device: DeviceProfile) -> str:
    ports = [22, 53, 80, 443, 3389, 8080, 8443]
    src_p = random.randint(1024, 65535)
    dst_p = random.choice(ports)
    src_ip = f"10.1.{random.randint(1, 254)}.{random.randint(1, 254)}"
    dst_ip = f"8.8.{random.randint(1, 254)}.{random.randint(1, 254)}"
    action = random.choice(["Deny", "Permit"])
    return (
        f'<164>Sep 29 2026 {datetime.now(timezone.utc).strftime("%H:%M:%S")}: '
        f'%ASA-4-106023: {action} tcp src outside:{src_ip}/{src_p} dst inside:{dst_ip}/{dst_p} '
        f'by access-group "acl_edge_policy"'
    )


def gen_smart_meter(device: DeviceProfile) -> str:
    kw = round(random.uniform(1.2, 18.5), 2)
    voltage = round(random.uniform(228.0, 242.0), 1)
    temp = round(random.uniform(32.0, 68.0), 1)
    status = "ALERT_HIGH_LOAD" if kw > 15.0 else "NORMAL"
    return (
        f"{datetime.now(timezone.utc).strftime('%b %d %H:%M:%S')} {device.device_id} "
        f"telemetry_grid power_kw={kw} line_voltage={voltage} transformer_temp_c={temp} status={status}"
    )


def gen_air_quality(device: DeviceProfile) -> str:
    pm25 = round(random.uniform(5.0, 65.0), 1)
    co2 = random.randint(400, 1600)
    humidity = round(random.uniform(35.0, 75.0), 1)
    air_status = "HAZARDOUS" if pm25 > 50.0 else "GOOD"
    return (
        f"{datetime.now(timezone.utc).strftime('%b %d %H:%M:%S')} {device.device_id} "
        f"air_monitor pm25={pm25} co2_ppm={co2} humidity_pct={humidity} status={air_status}"
    )


def gen_vibration(device: DeviceProfile) -> str:
    freq = round(random.uniform(50.0, 320.0), 1)
    vib_g = round(random.uniform(0.1, 2.5), 2)
    bearing_temp = round(random.uniform(40.0, 95.0), 1)
    health = "CRITICAL" if vib_g > 2.0 else "OPTIMAL"
    return (
        f"{datetime.now(timezone.utc).strftime('%b %d %H:%M:%S')} {device.device_id} "
        f"vibration_sensor bearing_hz={freq} g_force={vib_g} bearing_temp_c={bearing_temp} state={health}"
    )


def gen_linux_syslog(device: DeviceProfile) -> str:
    user = random.choice(["root", "admin", "service_scada", "operator"])
    src_ip = f"192.168.1.{random.randint(50, 200)}"
    port = random.randint(1024, 65535)
    return (
        f"{datetime.now(timezone.utc).strftime('%b %d %H:%M:%S')} {device.device_id} "
        f"sshd[{random.randint(1000, 65000)}]: Failed password for {user} from {src_ip} port {port} ssh2"
    )


GENERATORS = {
    "gen_cisco_asa": gen_cisco_asa,
    "gen_smart_meter": gen_smart_meter,
    "gen_air_quality": gen_air_quality,
    "gen_vibration": gen_vibration,
    "gen_linux_syslog": gen_linux_syslog,
}


# ── STREAM TRANSMITTERS ─────────────────────────────────────────────────────

class UdpTransmitter:
    def __init__(self, host: str = "127.0.0.1", port: int = 5140) -> None:
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(self, payload: str) -> None:
        self.sock.sendto(payload.encode("utf-8"), (self.host, self.port))

    def close(self) -> None:
        self.sock.close()


class HttpTransmitter:
    def __init__(self, endpoint: str = "http://127.0.0.1:4000/api/upload-csv") -> None:
        self.endpoint = endpoint

    def send(self, payload: str, source_ip: str = "127.0.0.1") -> str | None:
        try:
            req = urllib.request.Request(
                self.endpoint,
                data=json.dumps({"csv_content": payload, "source_ip": source_ip}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                res = json.loads(r.read())
                events = res.get("events", [])
                if events:
                    return events[0].get("lineage_id")
                return None
        except Exception:
            return None

    def send_batch(self, payloads: list[tuple[str, str]]) -> int:
        if not payloads:
            return 0
        try:
            csv_text = "\n".join(p[0] for p in payloads)
            src_ip = payloads[0][1] if payloads else "127.0.0.1"
            req = urllib.request.Request(
                self.endpoint,
                data=json.dumps({"csv_content": csv_text, "source_ip": src_ip}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                res = json.loads(r.read())
                return res.get("ingested_count", len(payloads))
        except Exception:
            return 0


# ── MAIN STREAM ENGINE ───────────────────────────────────────────────────────

def run_iot_stream(
    rate: float = 10.0,
    total_count: int | None = None,
    protocol: str = "http",
    udp_port: int = 5140,
    batch_size: int = 1,
) -> None:
    target_info = f"127.0.0.1:{udp_port}" if protocol == "udp" else "http://127.0.0.1:4000/api/upload-csv"
    print("\n" + "=" * 78)
    print("  ULPF REAL-TIME IoT & NETWORK MULTI-DEVICE STREAM ENGINE")
    print("=" * 78)
    print(f"  Target Ingestion: {protocol.upper()} -> {target_info}")
    print(f"  Target Rate:      {rate} events / second ({1.0/rate*1000:.1f}ms interval)")
    print(f"  Batching Mode:    {batch_size} log(s) per transmission payload")
    print(f"  Fleet Devices:    {len(DEVICE_FLEET)} heterogeneous simulated hardware nodes")
    print(f"  Live UI Queue:    http://localhost:3100/queue (Discovered IoT Clusters)")
    print(f"  Live UI Dashboard:http://localhost:3100/dashboard (Live EPS & Normalization)")
    print("-" * 78)

    for dev in DEVICE_FLEET:
        color = "\033[92m[HOT]\033[0m" if dev.expected_path == "HOT" else "\033[93m[COLD]\033[0m"
        print(f"  * {color} {dev.device_id:25} ({dev.ip:15}) -> {dev.category}")
    print("=" * 78 + "\n")

    udp_tx = UdpTransmitter(port=udp_port) if protocol == "udp" else None
    http_tx = HttpTransmitter() if protocol == "http" else None

    count = 0
    hot_count = 0
    cold_count = 0
    start_time = time.time()
    interval = (1.0 / max(rate, 0.1)) * max(batch_size, 1)

    print("Press Ctrl+C at any time to pause or exit stream.\n")

    batch_buffer: list[tuple[str, str, DeviceProfile]] = []

    try:
        while True:
            if total_count and count >= total_count:
                break

            # Pick a random device from fleet
            dev = random.choice(DEVICE_FLEET)
            gen_fn = GENERATORS[dev.generator_func]
            raw_log = gen_fn(dev)
            batch_buffer.append((raw_log, dev.ip, dev))

            if len(batch_buffer) >= batch_size:
                if protocol == "udp" and udp_tx:
                    for l, _, _ in batch_buffer:
                        udp_tx.send(l)
                elif protocol == "http" and http_tx:
                    if len(batch_buffer) == 1:
                        http_tx.send(batch_buffer[0][0], source_ip=batch_buffer[0][1])
                    else:
                        http_tx.send_batch([(item[0], item[1]) for item in batch_buffer])

                for _, _, item_dev in batch_buffer:
                    count += 1
                    if item_dev.expected_path == "HOT":
                        hot_count += 1
                    else:
                        cold_count += 1

                elapsed = time.time() - start_time
                current_eps = count / max(elapsed, 0.001)

                # Format live log preview
                last_log = batch_buffer[-1][0]
                last_dev = batch_buffer[-1][2]
                preview = last_log if len(last_log) <= 65 else last_log[:62] + "..."
                path_badge = (
                    "\033[92m[HOT PATH  -> SIEM]\033[0m"
                    if last_dev.expected_path == "HOT"
                    else "\033[93m[COLD PATH -> QUEUE]\033[0m"
                )

                sys.stdout.write(
                    f"\r[{count:05d}] {last_dev.ip:15} | {path_badge} | {current_eps:5.1f} EPS | {preview}\n"
                )
                sys.stdout.flush()

                batch_buffer = []
                time.sleep(interval)

    except KeyboardInterrupt:
        print("\n\n[!] Stream paused by user.")

    finally:
        if batch_buffer:
            if protocol == "http" and http_tx:
                http_tx.send_batch([(item[0], item[1]) for item in batch_buffer])
            count += len(batch_buffer)
        if udp_tx:
            udp_tx.close()

    total_time = time.time() - start_time
    avg_eps = count / max(total_time, 0.001)
    print("\n" + "=" * 78)
    print("  STREAM SESSION SUMMARY:")
    print(f"  * Total Events Ingested: {count:,}")
    print(f"  * Duration:              {total_time:.2f} seconds")
    print(f"  * Average Throughput:    {avg_eps:.1f} events/second (EPS)")
    print(f"  * Hot-Path Dispatches:   {hot_count:,} ({hot_count/max(count, 1)*100:.1f}%) -> OCSF 4001 to Sinks")
    print(f"  * Cold-Path Ingestions:  {cold_count:,} ({cold_count/max(count, 1)*100:.1f}%) -> Drain3 Review Queue")
    print("=" * 78)
    print("  Check live discovered clusters: http://localhost:3100/queue")
    print("  Check system dashboard:         http://localhost:3100/dashboard\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ULPF Real-Time IoT Multi-Device Stream Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 1. Real-time visual stream (Great for video demo):
  python tools/iot_live_stream.py --rate 10 --count 30

  # 2. Continuous real-time stream from all 5 devices:
  python tools/iot_live_stream.py --rate 15

  # 3. High-throughput burst (1,000 logs at 200 EPS):
  python tools/iot_live_stream.py --rate 200 --count 1000 --batch-size 25

  # 4. Stream over raw UDP socket:
  python tools/iot_live_stream.py --protocol udp --port 5140 --rate 20
        """,
    )

    parser.add_argument("--rate", "-r", type=float, default=10.0, help="Events per second (default: 10.0)")
    parser.add_argument("--count", "-c", type=int, default=None, help="Total number of events to stream (default: unlimited)")
    parser.add_argument("--batch-size", "-b", type=int, default=1, help="Events per network payload (default: 1, use 10-50 for high EPS)")
    parser.add_argument("--protocol", "-p", choices=["udp", "http"], default="http", help="Transport protocol (default: http)")
    parser.add_argument("--port", type=int, default=5140, help="Target Syslog UDP port (default: 5140)")

    args = parser.parse_args()
    run_iot_stream(
        rate=args.rate,
        total_count=args.count,
        protocol=args.protocol,
        udp_port=args.port,
        batch_size=args.batch_size,
    )


if __name__ == "__main__":
    main()
