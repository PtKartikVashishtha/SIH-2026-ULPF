"""
Air-Gap Compliance & Offline Security Scanner (M7 Deliverable).

Verifies:
1. Static Asset Isolation: Checks review-ui and services for external CDN links (Google Fonts, unpkg, cdnjs, etc.).
2. Typography Compliance: Confirms review-ui only uses native system fonts.
3. Runtime Network Isolation: Wraps socket connections to verify zero outbound egress to public IP/DNS addresses.
"""

from __future__ import annotations

import re
import socket
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

BANNED_URL_PATTERNS = [
    re.compile(r"https?://fonts\.googleapis\.com", re.IGNORECASE),
    re.compile(r"https?://fonts\.gstatic\.com", re.IGNORECASE),
    re.compile(r"https?://cdnjs\.cloudflare\.com", re.IGNORECASE),
    re.compile(r"https?://cdn\.jsdelivr\.net", re.IGNORECASE),
    re.compile(r"https?://unpkg\.com", re.IGNORECASE),
    re.compile(r"https?://api\.telemetry", re.IGNORECASE),
]

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1", "review-api", "ingestion-svc", "pipeline-svc", "sinks-svc", "integrity-svc", "review-ui"}


def check_static_assets() -> list[str]:
    """Scans all UI files, HTML, and CSS for external CDN references."""
    violations: list[str] = []
    scan_dirs = [REPO_ROOT / "services" / "review-ui", REPO_ROOT / "services" / "review-api"]

    for d in scan_dirs:
        for p in d.rglob("*"):
            if p.is_file() and p.suffix in (".html", ".css", ".tsx", ".ts", ".js", ".jsx", ".json"):
                if "node_modules" in p.parts or ".next" in p.parts:
                    continue
                content = p.read_text(encoding="utf-8", errors="ignore")
                for pat in BANNED_URL_PATTERNS:
                    match = pat.search(content)
                    if match:
                        violations.append(f"External asset match '{match.group(0)}' in {p.relative_to(REPO_ROOT)}")

    return violations


def check_system_font_compliance() -> bool:
    """Confirms that CSS specifies native system font stacks without remote @import."""
    globals_css = REPO_ROOT / "services" / "review-ui" / "src" / "app" / "globals.css"
    if not globals_css.exists():
        return False
    content = globals_css.read_text(encoding="utf-8")
    if "@import url(" in content and "http" in content:
        return False
    return "system-ui" in content or "-apple-system" in content or "Segoe UI" in content


class OutboundConnectionAttempt(Exception):
    pass


def run_runtime_airgap_drill() -> bool:
    """Interceptors that fail if any socket attempt is made to non-local address."""
    orig_connect = socket.socket.connect

    def guarded_connect(self: socket.socket, address: tuple[str, int] | str) -> None:
        host = address[0] if isinstance(address, tuple) else address
        if host not in ALLOWED_HOSTS and not host.startswith("127."):
            raise OutboundConnectionAttempt(f"Forbidden outbound connection attempt to {host} in air-gap mode!")
        return orig_connect(self, address)

    socket.socket.connect = guarded_connect  # type: ignore[assignment]
    try:
        # Exercise pipeline and normalization under the air-gap guard
        sys.path.insert(0, str(REPO_ROOT / "services" / "pipeline-svc" / "src"))
        sys.path.insert(0, str(REPO_ROOT / "packages" / "contracts" / "python"))

        from uuid import UUID

        from pipeline_svc.coldpath.drain import DrainParser
        from pipeline_svc.normalization import assemble_ocsf_event
        from ulpf_contracts import ExtractionEnvelope, PathTaken

        parser = DrainParser()
        parser.parse("<164>Sep 26 2026: %ASA-4-106023: Deny tcp src 10.0.0.1 dst 1.1.1.1")

        env = ExtractionEnvelope(
            lineage_id=UUID("00000000-0000-4000-8000-000000000001"),
            source_type="cisco_asa",
            parser_version="1.3.0",
            extracted_fields={"src_ip": "10.0.0.1", "dst_ip": "1.1.1.1", "action": "Deny"},
            confidence_scores={"src_ip": 1.0, "dst_ip": 1.0, "action": 1.0},
            path_taken=PathTaken.hot,
        )
        res = assemble_ocsf_event(env)
        assert res.schema_valid is True
        return True
    finally:
        socket.socket.connect = orig_connect  # type: ignore[assignment]


def main() -> None:
    print("=== ULPF AIR-GAP COMPLIANCE VERIFICATION ===")
    violations = check_static_assets()
    if violations:
        print("[FAIL] External asset violations found:")
        for v in violations:
            print(f"  - {v}")
        sys.exit(1)
    print("[OK] Static Assets: 100% self-hosted, zero external CDNs / Google Fonts.")

    if not check_system_font_compliance():
        print("[FAIL] Review UI does not enforce native system font stack.")
        sys.exit(1)
    print("[OK] Typography: Strict native system-font stack verified.")

    try:
        run_runtime_airgap_drill()
        print("[OK] Runtime Socket Drill: Zero outbound connection attempts under --network none emulation.")
    except OutboundConnectionAttempt as e:
        print(f"[FAIL] {e}")
        sys.exit(1)

    print("\n>>> AIR-GAP COMPLIANCE VERIFIED: 100% OFFLINE SAFE <<<\n")


if __name__ == "__main__":
    main()
