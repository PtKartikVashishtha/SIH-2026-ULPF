#!/usr/bin/env python3
"""
ULPF Unified CLI Log Ingestion & Normalization Client.
Takes raw logs directly from the command line or stdin and submits them
directly to the ULPF Ingestion Layer.

The exact same cluster pipeline (Ingestion -> WORM Raw Store -> Merkle Tree ->
Router -> Drain3 / Regex -> OCSF 4001 -> Review Queue / Sinks) processes every event.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

# Enable ANSI escape sequences on Windows
if os.name == "nt":
    os.system("")

API_URL = os.environ.get("ULPF_API_URL", "http://localhost:4000/api/upload-csv")
DASHBOARD_URL = os.environ.get("ULPF_UI_URL", "http://localhost:3100")


def submit_to_ingestion(raw_log: str, source_ip: str = "127.0.0.1") -> dict:
    """Submits the raw log directly to the unified Ingestion Layer."""
    raw_log = raw_log.strip().replace("\r", "")
    if not raw_log:
        return {}

    payload = {
        "csv_content": raw_log,
        "source_ip": source_ip,
    }

    req = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            records = data.get("records", [])
            return records[0] if records else {}
    except urllib.error.URLError as e:
        print(f"\n[-] Cluster connection failed ({e}).", file=sys.stderr)
        print("    Ensure the ULPF cluster is running (`docker compose up -d`).", file=sys.stderr)
        sys.exit(1)


def display_result(record: dict) -> None:
    if not record:
        return

    lineage_id = record.get("lineage_id", "unknown")
    path_taken = record.get("path_taken", "UNKNOWN")
    source_type = record.get("source_type", "unknown")
    sha256 = record.get("sha256_hash", "unknown")
    storage_ptr = record.get("storage_pointer", "unknown")
    extracted = record.get("extracted_fields", {})
    confidence = record.get("confidence_scores", {})
    cluster_id = record.get("cluster_id")
    schema_valid = record.get("schema_valid", False)
    class_uid = record.get("ocsf_class_uid", 4001)

    print("\n" + "=" * 76)
    print(f"RAW INPUT LOG:")
    print(f"  {record.get('sample_preview', '')}")
    print("=" * 76)

    # Ingestion & Cryptographic Proof
    print(f"[INGESTION LAYER]")
    print(f"  * Lineage ID:       {lineage_id}")
    print(f"  * SHA-256 Seal:     {sha256}")
    print(f"  * WORM Storage:     {storage_ptr}")
    print(f"  * Source IP:        {record.get('source_ip')}:{record.get('source_port')}")

    if path_taken == "HOT":
        # Hot Path
        print(f"\n\033[92m[PIPELINE ROUTER: HOT PATH (Pre-Compiled Regex Pack)]\033[0m")
        print(f"  * Pack / Source:    {source_type}")
        print(f"  * Extracted Fields: {json.dumps(extracted, indent=4)}")
        print(f"  * Confidence:       100% (High Confidence Engine)")

        print(f"\n\033[92m[CANONICAL OCSF 4001 (Network Activity)]\033[0m")
        print(f"  * Schema Valid:     {bool(schema_valid)} (Class UID: {class_uid})")
        print(f"  * Destination:      Dispatched directly to SIEM / Sinks (Hot Path bypasses queue)")
        print(f"  * Cryptographic UI: {DASHBOARD_URL}/trace/{lineage_id}")

    else:
        # Cold Path
        print(f"\n\033[93m[PIPELINE ROUTER: COLD PATH (Novel / Unmapped Log)]\033[0m")
        print(f"  * Drain3 Cluster:   {cluster_id or 'Auto-Clustered'}")
        print(f"  * Mined Tokens:     {json.dumps(extracted, indent=4)}")
        if confidence:
            print(f"  * Token Confidence: {json.dumps(confidence, indent=4)}")

        print(f"\n\033[93m[ANALYST ACTION REQUIRED]\033[0m")
        print(f"  * Review Queue:     {DASHBOARD_URL}/queue")
        print(f"  * Status:           Pending 1-click confirmation by security analyst")
        print(f"  * Cryptographic UI: {DASHBOARD_URL}/trace/{lineage_id}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ULPF Unified CLI Log Ingestion Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 1. Hot Path log (Cisco ASA):
  python tools/cli_normalize.py '<164>Sep 26 2026 12:00:00: %ASA-4-106023: Deny tcp src outside:10.1.1.50/49823 dst inside:8.8.8.8/443 by access-group "acl_outside"'

  # 2. Cold Path log (Novel unmapped log):
  python tools/cli_normalize.py "Sep 29 04:00:00 smart-meter-01 telemetry power_kw=14.2 line_v=239.1 temp=48.2C"

  # 3. Pipe logs from standard input:
  type my_logs.txt | python tools/cli_normalize.py --stdin
        """,
    )

    parser.add_argument("log", nargs="?", help="Raw log message string to submit")
    parser.add_argument("--ip", default="127.0.0.1", help="Source IP address of device (default: 127.0.0.1)")
    parser.add_argument("--file", "-f", help="Path to file containing raw logs (one per line)")
    parser.add_argument("--stdin", action="store_true", help="Read raw logs from standard input / pipe")

    args = parser.parse_args()

    if args.file:
        path = Path(args.file)
        if not path.exists():
            print(f"[-] File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rec = submit_to_ingestion(line, source_ip=args.ip)
                display_result(rec)
    elif args.stdin or (not sys.stdin.isatty() and not args.log):
        for line in sys.stdin:
            if line.strip():
                rec = submit_to_ingestion(line, source_ip=args.ip)
                display_result(rec)
    elif args.log:
        rec = submit_to_ingestion(args.log, source_ip=args.ip)
        display_result(rec)
    else:
        # Interactive prompt if no argument provided
        print("\n[ULPF Ingestion Client] Enter raw log message below (or Ctrl+C to exit):")
        try:
            user_log = input("Log > ").strip()
            if user_log:
                rec = submit_to_ingestion(user_log, source_ip=args.ip)
                display_result(rec)
        except KeyboardInterrupt:
            print("\nExiting.")


if __name__ == "__main__":
    main()
