"""
Comprehensive Multi-Vendor Perimeter Device Verification Suite (SIH26156 Requirements B & C).

Verifies that all 11 production perimeter device packs:
- Cisco ASA Firewall
- Fortinet FortiGate UTM
- Palo Alto Networks PAN-OS Firewall
- Check Point Gaia Firewall
- Juniper Networks SRX Services Gateway
- Suricata / Snort IDS/IPS
- Zeek (Bro) Network Monitor
- Linux Netfilter / iptables / UFW
- ArcSight Common Event Format (CEF)
- IBM QRadar LEEF
- RFC5424 Structured Syslog

Are cryptographically verified (Ed25519), loaded via RCU PackRegistry,
and route on the HOT PATH at 1.0 confidence into compliant OCSF 4001 events.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from ulpf_contracts import PathTaken

from pipeline_svc.normalization import assemble_ocsf_event
from pipeline_svc.pack_registry import PackRegistry
from pipeline_svc.router import Router

REPO_ROOT = Path(__file__).resolve().parents[3]
PUB_KEY_PATH = REPO_ROOT / "keys" / "dev_signing.pub"
PACKS_DIR = REPO_ROOT / "packs"


@pytest.fixture(scope="module")
def router() -> Router:
    pub_key_pem = PUB_KEY_PATH.read_bytes()
    registry = PackRegistry(public_key_pem=pub_key_pem)
    results = registry.reconcile_sweep(PACKS_DIR)
    # Ensure every single pack was compiled and accepted without quarantine
    assert all(results.values()), f"Some packs were quarantined: {registry.get_quarantined()}"
    return Router(registry=registry)


VENDOR_TEST_CASES = [
    {
        "vendor": "cisco_asa",
        "raw_log": '<164>Sep 26 2026 12:00:00: %ASA-4-106023: Deny tcp src outside:192.168.1.100/49823 dst inside:10.0.0.50/443 by access-group "acl_outside"',
        "expected_src_ip": "192.168.1.100",
        "expected_src_port": 49823,
        "expected_dst_ip": "10.0.0.50",
        "expected_dst_port": 443,
        "expected_action": "Refuse",
        "expected_proto": "tcp",
    },
    {
        "vendor": "fortinet_fortigate",
        "raw_log": 'date=2026-09-26 time=12:00:00 devname="FGT60D" devid="FGT60D123456" type="traffic" subtype="forward" level="notice" srcip=192.168.1.105 srcport=54321 dstip=10.0.0.80 dstport=80 proto=6 action="deny" policyid=1',
        "expected_src_ip": "192.168.1.105",
        "expected_src_port": 54321,
        "expected_dst_ip": "10.0.0.80",
        "expected_dst_port": 80,
        "expected_action": "Refuse",
        "expected_proto": "tcp",
    },
    {
        "vendor": "paloalto_panos",
        "raw_log": 'traffic,standard,1,2026/09/26 12:00:00 192.168.1.200:51234 -> 10.0.0.90:443 proto=tcp action=deny',
        "expected_src_ip": "192.168.1.200",
        "expected_src_port": 51234,
        "expected_dst_ip": "10.0.0.90",
        "expected_dst_port": 443,
        "expected_action": "Refuse",
        "expected_proto": "tcp",
    },
    {
        "vendor": "checkpoint_fw",
        "raw_log": 'Sep 26 12:00:00 cp-gateway CheckPoint: [action:"Drop"; proto:"tcp"; src:"192.168.2.50"; dst:"10.1.1.10"; sport:"41234"; dport:"22"; rule:"DropSSH";]',
        "expected_src_ip": "192.168.2.50",
        "expected_src_port": 41234,
        "expected_dst_ip": "10.1.1.10",
        "expected_dst_port": 22,
        "expected_action": "Refuse",
        "expected_proto": "tcp",
    },
    {
        "vendor": "juniper_srx",
        "raw_log": 'RT_FLOW: RT_FLOW_SESSION_CREATE: session created 192.168.3.10/61234->10.2.2.20/8080 None/None 6 basic-traffic zone-trust zone-untrust',
        "expected_src_ip": "192.168.3.10",
        "expected_src_port": 61234,
        "expected_dst_ip": "10.2.2.20",
        "expected_dst_port": 8080,
        "expected_action": "Open",
        "expected_proto": "tcp",
    },
    {
        "vendor": "suricata_ids",
        "raw_log": '[**] [1:2001219:19] ET SCAN Potential SSH Scan [**] [Priority: 2] {TCP} 192.168.4.15:48123 -> 10.3.3.30:22',
        "expected_src_ip": "192.168.4.15",
        "expected_src_port": 48123,
        "expected_dst_ip": "10.3.3.30",
        "expected_dst_port": 22,
        "expected_action": "Refuse",
        "expected_proto": "tcp",
    },
    {
        "vendor": "zeek_conn",
        "raw_log": '1727352000.123456 C9yZ1234567 192.168.5.25 55432 8.8.8.8 53 udp dns 0.05 45 120 S0',
        "expected_src_ip": "192.168.5.25",
        "expected_src_port": 55432,
        "expected_dst_ip": "8.8.8.8",
        "expected_dst_port": 53,
        "expected_action": "Traffic",
        "expected_proto": "udp",
    },
    {
        "vendor": "linux_iptables",
        "raw_log": '[UFW_BLOCK]: IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.6.40 DST=10.4.4.40 LEN=60 PROTO=TCP SPT=49123 DPT=23',
        "expected_src_ip": "192.168.6.40",
        "expected_src_port": 49123,
        "expected_dst_ip": "10.4.4.40",
        "expected_dst_port": 23,
        "expected_action": "Refuse",
        "expected_proto": "tcp",
    },
    {
        "vendor": "cef_perimeter",
        "raw_log": 'CEF:0|VendorX|FWGateway|1.0|100|PacketDropped|Medium|src=192.168.7.60 dst=10.5.5.50 spt=38123 dpt=443 proto=tcp act=deny',
        "expected_src_ip": "192.168.7.60",
        "expected_src_port": 38123,
        "expected_dst_ip": "10.5.5.50",
        "expected_dst_port": 443,
        "expected_action": "Refuse",
        "expected_proto": "tcp",
    },
    {
        "vendor": "leef_perimeter",
        "raw_log": 'LEEF:2.0|IBM|QRadarFW|7.3.0|SessionDrop|src=192.168.8.70|dst=10.6.6.60|srcPort=39123|dstPort=80|proto=tcp|action=drop',
        "expected_src_ip": "192.168.8.70",
        "expected_src_port": 39123,
        "expected_dst_ip": "10.6.6.60",
        "expected_dst_port": 80,
        "expected_action": "Refuse",
        "expected_proto": "tcp",
    },
    {
        "vendor": "syslog_rfc5424",
        "raw_log": '<134>1 2026-09-26T12:00:00.000Z myfirewall.corp edge-gw 1234 msg-01 - DENY TCP src=192.168.9.80:44123 dst=10.7.7.70:80',
        "expected_src_ip": "192.168.9.80",
        "expected_src_port": 44123,
        "expected_dst_ip": "10.7.7.70",
        "expected_dst_port": 80,
        "expected_action": "Refuse",
        "expected_proto": "tcp",
    },
]


@pytest.mark.parametrize("tc", VENDOR_TEST_CASES, ids=[tc["vendor"] for tc in VENDOR_TEST_CASES])
def test_all_perimeter_vendors_hot_path_and_ocsf(router: Router, tc: dict) -> None:
    lineage_id = uuid.uuid4()
    raw_log = tc["raw_log"]

    # 1. Hot-path deterministic route & extraction
    envelope = router.route_and_extract(raw_log, lineage_id, enable_cold_path=False)
    assert envelope is not None, f"Failed to match hot path for vendor: {tc['vendor']}"
    assert envelope.path_taken == PathTaken.hot
    assert envelope.source_type == tc["vendor"]
    assert envelope.confidence_scores["src_ip"] == 1.0

    # 2. OCSF Normalization
    result = assemble_ocsf_event(envelope, raw_data_ptr="raw_store://chunk_demo/offset_1")
    assert result.schema_valid is True, f"OCSF validation failed for {tc['vendor']}: {result.validation_errors}"
    assert result.ocsf_event is not None

    ocsf = result.ocsf_event
    # Verify core OCSF fields
    assert ocsf.class_uid == 4001
    assert ocsf.category_uid == 4
    assert ocsf.src_endpoint.ip == tc["expected_src_ip"]
    assert ocsf.src_endpoint.port == tc["expected_src_port"]
    assert ocsf.dst_endpoint.ip == tc["expected_dst_ip"]
    assert ocsf.dst_endpoint.port == tc["expected_dst_port"]
    assert ocsf.activity_name == tc["expected_action"]
    assert ocsf.connection_info is not None
    assert ocsf.connection_info.protocol_name == tc["expected_proto"]

    # Invariant: metadata.uid == _lineage_id
    assert str(ocsf.metadata.uid) == str(lineage_id)
    assert str(ocsf.field_lineage_id) == str(lineage_id)
