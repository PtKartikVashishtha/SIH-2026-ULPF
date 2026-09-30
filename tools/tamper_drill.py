#!/usr/bin/env python3
"""
ULPF Tamper Demonstration & Merkle Tree Verification Tool.
Designed for live video demonstrations and evaluation audits.

Demonstrates:
  1. How directly tampering with the database (SQLite) breaks the cryptographic seal.
  2. How tampering with raw storage (.zst bytes) breaks the Merkle tree leaf hash.
  3. Real-time transition in the UI (http://localhost:3100/trace/<id>) from:
     [CRYPTOGRAPHIC INTEGRITY VERIFIED (ANCHORED)] -> [CRITICAL SECURITY ALERT: TAMPER DETECTED]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import subprocess
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKUP_FILE = REPO_ROOT / "data" / ".tamper_backup.json"
DEFAULT_LINEAGE_ID = "d47683d1-aea7-494d-a7db-e6982cb87720"


def print_banner(text: str) -> None:
    border = "=" * len(text)
    print(f"\n{border}\n{text}\n{border}\n")


def execute_in_container(cmd: str) -> str:
    """Executes a command inside the ulpf-pipeline-svc container which mounts the shared ulpf_data volume."""
    try:
        res = subprocess.run(
            ["docker", "exec", "ulpf-pipeline-svc", "sh", "-c", cmd],
            capture_output=True,
            text=True,
            check=True,
        )
        return res.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Docker exec failed: {e.stderr}", file=sys.stderr)
        return ""


def get_verify_api(lineage_id: str) -> dict:
    url = f"http://localhost:4000/verify/{lineage_id}"
    req = urllib.request.Request(url, headers={"User-Agent": "ULPF-TamperDrill/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e), "verified": False}


def verify_status(lineage_id: str) -> None:
    print_banner(f"CHECKING CRYPTOGRAPHIC INTEGRITY: {lineage_id}")

    res = get_verify_api(lineage_id)
    if "error" in res and not res.get("tampered"):
        print(f"[-] API Error: {res.get('error')}")
        return

    tampered = res.get("tampered", False)
    verified = res.get("verified", False)
    stored_hash = res.get("sha256_hash", "N/A")
    disk_hash = res.get("actual_raw_hash", "N/A")
    root_hash = res.get("merkle_root_hash", "N/A")
    chunk_id = res.get("chunk_id", "N/A")
    leaf_idx = res.get("merkle_leaf_index", 0)

    print(f"[*] Lineage ID:         {lineage_id}")
    print(f"[*] Merkle Chunk:        {chunk_id} (Leaf #{leaf_idx})")
    print(f"[*] DB Recorded Seal:    {stored_hash}")
    print(f"[*] Actual Disk Seal:    {disk_hash}")
    print(f"[*] Anchored Merkle Root: {root_hash}")
    print("-" * 60)

    if tampered:
        print("\033[91m[!] STATUS: TAMPER DETECTED! (CRYPTOGRAPHIC SEAL BROKEN)\033[0m")
        print(f"\033[91m[!] Reason: {res.get('tamper_reason')}\033[0m")
        print("\n--> View live in UI: \033[94mhttp://localhost:3100/trace/" + lineage_id + "\033[0m (Shows RED Alert Banner)")
    elif verified:
        print("\033[92m[OK] STATUS: VERIFIED AUTHENTIC (ANCHORED & IMMUTABLE)\033[0m")
        print(f"[OK] {res.get('proof_message')}")
        print("\n--> View live in UI: \033[94mhttp://localhost:3100/trace/" + lineage_id + "\033[0m (Shows GREEN Verified Banner)")
    else:
        print("\033[93m[?] STATUS: PENDING ANCHORING\033[0m")


def tamper_database(lineage_id: str) -> None:
    print_banner(f"SIMULATING DATABASE INTRUSION ON LINEAGE: {lineage_id}")

    # 1. Fetch current hash from container DB
    out = execute_in_container(
        f"python -c \"import sqlite3; conn = sqlite3.connect('/app/data/ulpf.db'); "
        f"r = conn.execute('SELECT sha256_hash FROM raw_events WHERE lineage_id = ?', ('{lineage_id}',)).fetchone(); "
        f"print(r[0] if r else '')\""
    )

    if not out:
        print(f"[-] Could not find lineage_id {lineage_id} in container DB.")
        return

    original_hash = out.strip()
    if original_hash.startswith("deadbeef"):
        verify_data = get_verify_api(lineage_id)
        if verify_data.get("actual_raw_hash"):
            original_hash = verify_data["actual_raw_hash"]

    # 2. Save backup
    backup = {}
    if BACKUP_FILE.exists():
        try:
            backup = json.loads(BACKUP_FILE.read_text())
        except Exception:
            backup = {}
    if not backup.get(lineage_id) or backup.get(lineage_id, "").startswith("deadbeef"):
        backup[lineage_id] = original_hash
    BACKUP_FILE.parent.mkdir(parents=True, exist_ok=True)
    BACKUP_FILE.write_text(json.dumps(backup, indent=2))

    # 3. Corrupt hash in DB: replace first 8 chars with 'deadbeef'
    tampered_hash = "deadbeef" + original_hash[8:]

    execute_in_container(
        f"python -c \"import sqlite3; conn = sqlite3.connect('/app/data/ulpf.db'); "
        f"conn.execute('UPDATE raw_events SET sha256_hash = ? WHERE lineage_id = ?', ('{tampered_hash}', '{lineage_id}')); "
        f"conn.commit()\""
    )

    # Also update local ulpf.db if present
    local_db = REPO_ROOT / "ulpf.db"
    if local_db.exists():
        with sqlite3.connect(local_db) as conn:
            conn.execute("UPDATE raw_events SET sha256_hash = ? WHERE lineage_id = ?", (tampered_hash, lineage_id))
            conn.commit()

    print("[*] Attack Action: Attacker modified SQLite row directly!")
    print(f"    - Original Authentic Hash: {original_hash}")
    print(f"    - Tampered Database Hash:  \033[91m{tampered_hash}\033[0m")
    print("\n[!] The database hash is now corrupted, but the immutable storage chunk remains untouched.")
    print("-" * 60)
    verify_status(lineage_id)


def restore_database(lineage_id: str) -> None:
    print_banner(f"RESTORING AUTHENTIC DATABASE STATE: {lineage_id}")

    backup = {}
    if BACKUP_FILE.exists():
        try:
            backup = json.loads(BACKUP_FILE.read_text())
        except Exception:
            backup = {}

    # 1. Restore leaf hash from backup or query the authentic disk seal directly
    original_hash = backup.get(lineage_id)
    if not original_hash or original_hash.startswith("deadbeef"):
        verify_data = get_verify_api(lineage_id)
        if verify_data.get("actual_raw_hash") and not verify_data["actual_raw_hash"].startswith("deadbeef"):
            original_hash = verify_data["actual_raw_hash"]
        else:
            raw_out = execute_in_container(
                f"python -c \"import urllib.request, hashlib, sqlite3; "
                f"conn = sqlite3.connect('/app/data/ulpf.db'); "
                f"ptr = conn.execute('SELECT storage_pointer FROM raw_events WHERE lineage_id = ?', ('{lineage_id}',)).fetchone()[0]; "
                f"data = urllib.request.urlopen('http://localhost:8000/raw?pointer=' + urllib.parse.quote(ptr)).read(); "
                f"print(hashlib.sha256(data).hexdigest())\""
            )
            original_hash = raw_out.strip()

    if original_hash:
        execute_in_container(
            f"python -c \"import sqlite3; conn = sqlite3.connect('/app/data/ulpf.db'); "
            f"conn.execute('UPDATE raw_events SET sha256_hash = ? WHERE lineage_id = ?', ('{original_hash}', '{lineage_id}')); "
            f"conn.commit()\""
        )
        print(f"[OK] Restored authentic leaf SHA-256 seal: \033[92m{original_hash}\033[0m")

    # 2. Restore chunk merkle root if corrupted
    out = execute_in_container(
        f"python -c \"import sqlite3; conn = sqlite3.connect('/app/data/ulpf.db'); "
        f"cid = conn.execute('SELECT chunk_id FROM raw_events WHERE lineage_id = ?', ('{lineage_id}',)).fetchone()[0]; "
        f"print(cid)\""
    )
    if out:
        chunk_id = out.strip()
        original_root = backup.get(f"root_{chunk_id}")
        if not original_root or original_root.startswith("badroot"):
            recomp = execute_in_container(
                f"python -c \"import sqlite3, hashlib; "
                f"conn = sqlite3.connect('/app/data/ulpf.db'); "
                f"rows = conn.execute('SELECT sha256_hash FROM raw_events WHERE chunk_id = ? ORDER BY lineage_id ASC', ('{chunk_id}',)).fetchall(); "
                f"leaves = [hashlib.sha256(b'\\x00' + bytes.fromhex(r[0])).digest() for r in rows]; "
                f"curr = leaves; "
                f"while len(curr) > 1: "
                f"    nxt = []; "
                f"    for i in range(0, len(curr), 2): "
                f"        l = curr[i]; r = curr[i+1] if i+1 < len(curr) else l; "
                f"        nxt.append(hashlib.sha256(b'\\x01' + l + r).digest()); "
                f"    curr = nxt; "
                f"print(curr[0].hex() if curr else '')\""
            )
            original_root = recomp.strip()

        if original_root:
            execute_in_container(
                f"python -c \"import sqlite3; conn = sqlite3.connect('/app/data/ulpf.db'); "
                f"conn.execute('UPDATE merkle_chunks SET merkle_root_hash = ? WHERE chunk_id = ?', ('{original_root}', '{chunk_id}')); "
                f"conn.commit()\""
            )
            print(f"[OK] Restored authentic Merkle root: \033[92m{original_root}\033[0m")

    print("-" * 60)
    verify_status(lineage_id)


def tamper_merkle_root(lineage_id: str) -> None:
    print_banner(f"SIMULATING DATABASE MERKLE ROOT TAMPERING: {lineage_id}")

    # 1. Get chunk_id and original root
    out = execute_in_container(
        f"python -c \"import sqlite3; conn = sqlite3.connect('/app/data/ulpf.db'); "
        f"cid = conn.execute('SELECT chunk_id FROM raw_events WHERE lineage_id = ?', ('{lineage_id}',)).fetchone()[0]; "
        f"root = conn.execute('SELECT merkle_root_hash FROM merkle_chunks WHERE chunk_id = ?', (cid,)).fetchone()[0]; "
        f"print(f'{{cid}}|{{root}}')\""
    )
    if not out or "|" not in out:
        print("[-] Could not retrieve chunk or root hash.")
        return

    chunk_id, original_root = out.split("|", 1)

    # 2. Save backup
    backup = {}
    if BACKUP_FILE.exists():
        try:
            backup = json.loads(BACKUP_FILE.read_text())
        except Exception:
            backup = {}
    backup[f"root_{chunk_id}"] = original_root
    BACKUP_FILE.write_text(json.dumps(backup, indent=2))

    # 3. Corrupt root in DB
    tampered_root = "badroot0" + original_root[8:]
    execute_in_container(
        f"python -c \"import sqlite3; conn = sqlite3.connect('/app/data/ulpf.db'); "
        f"conn.execute('UPDATE merkle_chunks SET merkle_root_hash = ? WHERE chunk_id = ?', ('{tampered_root}', '{chunk_id}')); "
        f"conn.commit()\""
    )

    print(f"[*] Attack Action: Corrupted Merkle Root in SQLite table `merkle_chunks` for {chunk_id}!")
    print(f"    - Original Authentic Root: {original_root}")
    print(f"    - Tampered Root in DB:     \033[91m{tampered_root}\033[0m")
    print("-" * 60)
    verify_status(lineage_id)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ULPF Merkle Tree & Tamper Demonstration CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Video Demonstration Guide:
  1. Show authentic verified state:
     python tools/tamper_drill.py --verify
     -> Open browser: http://localhost:3100/trace/d47683d1-aea7-494d-a7db-e6982cb87720 (Shows GREEN Verified Banner)

  2. Simulate Database Intrusion (Attacker modifies SQLite raw_events row):
     python tools/tamper_drill.py --tamper-db
     -> Refresh browser: Instant RED TAMPER ALERT banner!

  3. Restore Authentic Database State:
     python tools/tamper_drill.py --restore
     -> Refresh browser: Returns to GREEN Verified!
        """,
    )

    parser.add_argument("--lineage-id", "-i", default=DEFAULT_LINEAGE_ID, help="Target event UUID (default: d47683d1-aea7-494d-a7db-e6982cb87720)")
    parser.add_argument("--verify", "-v", action="store_true", help="Check verification status via API")
    parser.add_argument("--tamper-db", "-t", action="store_true", help="Simulate database tampering by corrupting SQLite sha256_hash")
    parser.add_argument("--tamper-root", action="store_true", help="Simulate database tampering by corrupting SQLite merkle_root_hash")
    parser.add_argument("--restore", "-r", action="store_true", help="Restore original authentic state in SQLite")

    args = parser.parse_args()

    if args.tamper_db:
        tamper_database(args.lineage_id)
    elif args.tamper_root:
        tamper_merkle_root(args.lineage_id)
    elif args.restore:
        restore_database(args.lineage_id)
    else:
        # Default action: verify status
        verify_status(args.lineage_id)


if __name__ == "__main__":
    main()
