"""
Sign and generate production-grade signed mapping packs for top perimeter security appliances.
Covers:
- Cisco ASA Firewall (expanded)
- Fortinet FortiGate Firewall
- Palo Alto Networks PAN-OS (Traffic & Threat)
- Check Point Gaia Firewall
- Juniper Networks SRX Series Gateway
- Suricata / Snort IDS/IPS
- Zeek (Bro) Connection Monitor
- Linux Netfilter / iptables / UFW
- ArcSight Common Event Format (CEF) Perimeter
- IBM QRadar LEEF Perimeter
- RFC5424 Structured Syslog Perimeter
"""

from __future__ import annotations

import sys
from pathlib import Path
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "services" / "pipeline-svc" / "src"))

from pipeline_svc.crypto import sign_pack, verify_pack_signature

PRIV_KEY_PATH = REPO_ROOT / "keys" / "dev_signing.key"
PUB_KEY_PATH = REPO_ROOT / "keys" / "dev_signing.pub"
VENDORS_DIR = REPO_ROOT / "packs" / "vendors"

PACKS = [
    {
        "pack_id": "cisco_asa_v1.3.0",
        "source_type": "cisco_asa",
        "version": "1.3.0",
        "description": "Cisco Adaptive Security Appliance (ASA) Firewall mapping pack",
        "parent_pack_id": "base_network_v1.0.0",
        "signatures": [
            {
                "name": "asa_deny_106023",
                "pattern": r'%ASA-4-106023:\s+(?P<action>Deny|Permit)\s+(?P<protocol>\w+)\s+src\s+(?P<src_interface>\w+):(?P<src_ip>\d+\.\d+\.\d+\.\d+)/(?P<src_port>\d+)\s+dst\s+(?P<dst_interface>\w+):(?P<dst_ip>\d+\.\d+\.\d+\.\d+)/(?P<dst_port>\d+)(\s+by\s+access-group\s+"?(?P<acl_name>[^"\s]+)"?)?',
                "extracted_fields": {
                    "action": "$action",
                    "protocol": "$protocol",
                    "src_interface": "$src_interface",
                    "src_ip": "$src_ip",
                    "src_port": "$src_port",
                    "dst_interface": "$dst_interface",
                    "dst_ip": "$dst_ip",
                    "dst_port": "$dst_port",
                    "acl_name": "$acl_name",
                },
            },
            {
                "name": "asa_teardown_302014",
                "pattern": r'%ASA-6-302014:\s+Teardown\s+(?P<protocol>\w+)\s+connection\s+(?P<conn_id>\d+)\s+for\s+(?P<src_interface>\w+):(?P<src_ip>\d+\.\d+\.\d+\.\d+)/(?P<src_port>\d+)\s+to\s+(?P<dst_interface>\w+):(?P<dst_ip>\d+\.\d+\.\d+\.\d+)/(?P<dst_port>\d+)\s+duration\s+(?P<duration>[0-9:]+)\s+bytes\s+(?P<bytes>\d+)',
                "extracted_fields": {
                    "action": "Teardown",
                    "protocol": "$protocol",
                    "src_ip": "$src_ip",
                    "src_port": "$src_port",
                    "dst_ip": "$dst_ip",
                    "dst_port": "$dst_port",
                    "bytes": "$bytes",
                },
            },
            {
                "name": "asa_built_302013",
                "pattern": r'%ASA-6-302013:\s+Built\s+(?P<direction>inbound|outbound)\s+(?P<protocol>\w+)\s+connection\s+(?P<conn_id>\d+)\s+for\s+(?P<src_interface>\w+):(?P<src_ip>\d+\.\d+\.\d+\.\d+)/(?P<src_port>\d+)(\s+\([^)]*\))?\s+to\s+(?P<dst_interface>\w+):(?P<dst_ip>\d+\.\d+\.\d+\.\d+)/(?P<dst_port>\d+)(\s+\([^)]*\))?',
                "extracted_fields": {
                    "action": "Open",
                    "protocol": "$protocol",
                    "src_ip": "$src_ip",
                    "src_port": "$src_port",
                    "dst_ip": "$dst_ip",
                    "dst_port": "$dst_port",
                    "direction": "$direction",
                    "conn_id": "$conn_id",
                },
            },
            {
                "name": "asa_built_udp_302015",
                "pattern": r'%ASA-6-302015:\s+Built\s+(?P<direction>inbound|outbound)\s+UDP\s+connection\s+(?P<conn_id>\d+)\s+for\s+(?P<src_interface>\w+):(?P<src_ip>\d+\.\d+\.\d+\.\d+)/(?P<src_port>\d+)(\s+\([^)]*\))?\s+to\s+(?P<dst_interface>\w+):(?P<dst_ip>\d+\.\d+\.\d+\.\d+)/(?P<dst_port>\d+)',
                "extracted_fields": {
                    "action": "Open",
                    "protocol": "udp",
                    "src_ip": "$src_ip",
                    "src_port": "$src_port",
                    "dst_ip": "$dst_ip",
                    "dst_port": "$dst_port",
                    "direction": "$direction",
                    "conn_id": "$conn_id",
                },
            },
            {
                "name": "asa_teardown_udp_302016",
                "pattern": r'%ASA-6-302016:\s+Teardown\s+UDP\s+connection\s+(?P<conn_id>\d+)\s+for\s+(?P<src_interface>\w+):(?P<src_ip>\d+\.\d+\.\d+\.\d+)/(?P<src_port>\d+)\s+to\s+(?P<dst_interface>\w+):(?P<dst_ip>\d+\.\d+\.\d+\.\d+)/(?P<dst_port>\d+)\s+duration\s+(?P<duration>[0-9:]+)\s+bytes\s+(?P<bytes>\d+)',
                "extracted_fields": {
                    "action": "Teardown",
                    "protocol": "udp",
                    "src_ip": "$src_ip",
                    "src_port": "$src_port",
                    "dst_ip": "$dst_ip",
                    "dst_port": "$dst_port",
                    "bytes": "$bytes",
                },
            },
            {
                "name": "asa_acl_106100",
                "pattern": r'%ASA-6-106100:\s+access-list\s+(?P<acl_name>\S+)\s+(?P<action>denied|permitted)\s+(?P<protocol>\w+)\s+(?P<src_interface>\w+)/(?P<src_ip>\d+\.\d+\.\d+\.\d+)\((?P<src_port>\d+)\)\s+->\s+(?P<dst_interface>\w+)/(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\((?P<dst_port>\d+)\)',
                "extracted_fields": {
                    "action": "$action",
                    "protocol": "$protocol",
                    "src_ip": "$src_ip",
                    "src_port": "$src_port",
                    "dst_ip": "$dst_ip",
                    "dst_port": "$dst_port",
                    "acl_name": "$acl_name",
                },
            },
            {
                "name": "asa_acl_tcp_710003",
                "pattern": r'%ASA-3-710003:\s+TCP\s+access\s+(?P<action>denied)\s+by\s+ACL\s+from\s+(?P<src_interface>\w+):(?P<src_ip>\d+\.\d+\.\d+\.\d+)/(?P<src_port>\d+)\s+to\s+(?P<dst_interface>\w+):(?P<dst_ip>\d+\.\d+\.\d+\.\d+)/(?P<dst_port>\d+)',
                "extracted_fields": {
                    "action": "Refuse",
                    "protocol": "tcp",
                    "src_ip": "$src_ip",
                    "src_port": "$src_port",
                    "dst_ip": "$dst_ip",
                    "dst_port": "$dst_port",
                },
            },
            {
                "name": "asa_icmp_denied_313004",
                "pattern": r'%ASA-5-313004:\s+(?P<action>Denied)\s+ICMP\s+type\s+(?P<icmp_type>\d+)\s+code\s+(?P<icmp_code>\d+)\s+from\s+(?P<src_interface>\w+):(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+to\s+(?P<dst_interface>\w+):(?P<dst_ip>\d+\.\d+\.\d+\.\d+)',
                "extracted_fields": {
                    "action": "Refuse",
                    "protocol": "icmp",
                    "src_ip": "$src_ip",
                    "dst_ip": "$dst_ip",
                },
            },
            {
                "name": "asa_icmp_error_313005",
                "pattern": r'%ASA-5-313005:\s+No\s+matching\s+connection\s+for\s+ICMP\s+error\s+message:\s+icmp\s+src\s+(?P<src_interface>\w+):(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+dst\s+(?P<dst_interface>\w+):(?P<dst_ip>\d+\.\d+\.\d+\.\d+)',
                "extracted_fields": {
                    "action": "Traffic",
                    "protocol": "icmp",
                    "src_ip": "$src_ip",
                    "dst_ip": "$dst_ip",
                },
            },
            {
                "name": "asa_auth_failed_106012",
                "pattern": r'%ASA-5-106012:\s+User\s+authentication\s+(?P<action>failed)\s+for\s+user\s+(?P<user>\S+)\s+from\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)',
                "extracted_fields": {
                    "action": "Refuse",
                    "protocol": "tcp",
                    "src_ip": "$src_ip",
                    "user": "$user",
                },
            },
            {
                "name": "asa_auth_ok_113005",
                "pattern": r'%ASA-6-113005:\s+AAA\s+user\s+authentication\s+(?P<action>successful)\s+for\s+user\s+(?P<user>\S+)\s+from\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)',
                "extracted_fields": {
                    "action": "Open",
                    "protocol": "tcp",
                    "src_ip": "$src_ip",
                    "user": "$user",
                },
            },
            {
                "name": "asa_vpn_716001",
                "pattern": r'%ASA-6-716001:\s+Group\s+<(?P<group>[^>]+)>\s+User\s+<(?P<user>[^>]+)>\s+IP\s+<(?P<src_ip>\d+\.\d+\.\d+\.\d+)>\s+(?P<action>assigned)',
                "extracted_fields": {
                    "action": "Open",
                    "protocol": "tcp",
                    "src_ip": "$src_ip",
                    "user": "$user",
                    "group": "$group",
                },
            },
            {
                "name": "asa_vpn_716002",
                "pattern": r'%ASA-6-716002:\s+Group\s+<(?P<group>[^>]+)>\s+User\s+<(?P<user>[^>]+)>\s+IP\s+<(?P<src_ip>\d+\.\d+\.\d+\.\d+)>\s+(?P<action>disconnected)',
                "extracted_fields": {
                    "action": "Close",
                    "protocol": "tcp",
                    "src_ip": "$src_ip",
                    "user": "$user",
                    "group": "$group",
                },
            },
            {
                "name": "asa_ipsec_402116",
                "pattern": r'%ASA-4-402116:\s+IPsec:\s+Received\s+an\s+invalid\s+packet\s+from\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)',
                "extracted_fields": {
                    "action": "Refuse",
                    "protocol": "ipsec",
                    "src_ip": "$src_ip",
                },
            },
            {
                "name": "asa_ikev2_602304",
                "pattern": r'%ASA-6-602304:\s+IPSEC:\s+An\s+IKEv2\s+SA\s+was\s+(?P<action>established)\s+with\s+peer\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)',
                "extracted_fields": {
                    "action": "Open",
                    "protocol": "udp",
                    "src_ip": "$src_ip",
                },
            },
            {
                "name": "asa_ikev2_602305",
                "pattern": r'%ASA-6-602305:\s+IPSEC:\s+An\s+IKEv2\s+SA\s+was\s+(?P<action>deleted)\s+with\s+peer\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)',
                "extracted_fields": {
                    "action": "Close",
                    "protocol": "udp",
                    "src_ip": "$src_ip",
                },
            },
            {
                "name": "asa_threat_733100",
                "pattern": r'%ASA-4-733100:\s+Threat\s+Detection\s+detected\s+a\s+high\s+rate\s+of\s+connections\s+from\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)',
                "extracted_fields": {
                    "action": "Traffic",
                    "protocol": "tcp",
                    "src_ip": "$src_ip",
                },
            },
        ],
        "signer_key_id": "dev_signing",
    },
    {
        "pack_id": "fortinet_fortigate_v1.0.0",
        "source_type": "fortinet_fortigate",
        "version": "1.0.0",
        "description": "Fortinet FortiGate UTM/Next-Gen Firewall key-value log mapping pack",
        "parent_pack_id": "base_network_v1.0.0",
        "signatures": [
            {
                "name": "fortigate_traffic",
                "pattern": r'type="?traffic"?\s+.*subtype="?(?P<subtype>[^"\s]+)"?\s+.*srcip=(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+srcport=(?P<src_port>\d+)\s+.*dstip=(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\s+dstport=(?P<dst_port>\d+)\s+.*proto=(?P<proto>\d+|\w+)\s+.*action="?(?P<action>accept|deny|close|client-rst|server-rst|timeout|block)"?',
                "extracted_fields": {
                    "action": "$action",
                    "protocol": "$proto",
                    "src_ip": "$src_ip",
                    "src_port": "$src_port",
                    "dst_ip": "$dst_ip",
                    "dst_port": "$dst_port",
                    "subtype": "$subtype",
                },
            },
            {
                "name": "fortigate_utm_event",
                "pattern": r'type="?utm"?\s+.*subtype="?(?P<subtype>[^"\s]+)"?\s+.*eventtype="?(?P<eventtype>[^"\s]+)"?\s+.*srcip=(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+.*dstip=(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\s+.*action="?(?P<action>passthrough|blocked|dropped|monitored)"?',
                "extracted_fields": {
                    "action": "$action",
                    "src_ip": "$src_ip",
                    "dst_ip": "$dst_ip",
                    "subtype": "$subtype",
                    "eventtype": "$eventtype",
                },
            },
        ],
        "signer_key_id": "dev_signing",
    },
    {
        "pack_id": "paloalto_panos_v1.0.0",
        "source_type": "paloalto_panos",
        "version": "1.0.0",
        "description": "Palo Alto Networks PAN-OS Firewall Traffic & Threat CSV mapping pack",
        "parent_pack_id": "base_network_v1.0.0",
        "signatures": [
            {
                "name": "panos_traffic_csv",
                "pattern": r'^(?:[^,]*,){6}(?P<time_generated>[^,]*),(?P<src_ip>\d+\.\d+\.\d+\.\d+),(?P<dst_ip>\d+\.\d+\.\d+\.\d+),(?:[^,]*,){15}(?P<src_port>\d+),(?P<dst_port>\d+),(?:[^,]*,){3}(?P<protocol>\w+),(?P<action>allow|deny|drop|reset-client|reset-server|reset-both)',
                "extracted_fields": {
                    "action": "$action",
                    "protocol": "$protocol",
                    "src_ip": "$src_ip",
                    "src_port": "$src_port",
                    "dst_ip": "$dst_ip",
                    "dst_port": "$dst_port",
                },
            },
            {
                "name": "panos_syslog_kv",
                "pattern": r'traffic,.*?(?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+)\s+->\s+(?P<dst_ip>\d+\.\d+\.\d+\.\d+):(?P<dst_port>\d+)\s+proto=(?P<protocol>\w+)\s+action=(?P<action>allow|deny|drop)',
                "extracted_fields": {
                    "action": "$action",
                    "protocol": "$protocol",
                    "src_ip": "$src_ip",
                    "src_port": "$src_port",
                    "dst_ip": "$dst_ip",
                    "dst_port": "$dst_port",
                },
            },
        ],
        "signer_key_id": "dev_signing",
    },
    {
        "pack_id": "checkpoint_fw_v1.0.0",
        "source_type": "checkpoint_fw",
        "version": "1.0.0",
        "description": "Check Point Gaia Firewall log mapping pack",
        "parent_pack_id": "base_network_v1.0.0",
        "signatures": [
            {
                "name": "checkpoint_traffic_drop_accept",
                "pattern": r'CheckPoint.*?action[:=]"?(?P<action>Drop|Accept|Reject|drop|accept|reject)"?;\s+.*?proto[:=]"?(?P<protocol>\w+)"?;\s+.*?src[:=]"?(?P<src_ip>\d+\.\d+\.\d+\.\d+)"?;\s+.*?dst[:=]"?(?P<dst_ip>\d+\.\d+\.\d+\.\d+)"?;\s+.*?sport[:=]"?(?P<src_port>\d+)"?;\s+.*?dport[:=]"?(?P<dst_port>\d+)"?',
                "extracted_fields": {
                    "action": "$action",
                    "protocol": "$protocol",
                    "src_ip": "$src_ip",
                    "src_port": "$src_port",
                    "dst_ip": "$dst_ip",
                    "dst_port": "$dst_port",
                },
            },
        ],
        "signer_key_id": "dev_signing",
    },
    {
        "pack_id": "juniper_srx_v1.0.0",
        "source_type": "juniper_srx",
        "version": "1.0.0",
        "description": "Juniper Networks SRX Series Flow session mapping pack",
        "parent_pack_id": "base_network_v1.0.0",
        "signatures": [
            {
                "name": "juniper_srx_flow_session",
                "pattern": r'RT_FLOW:\s+(?P<event_type>RT_FLOW_SESSION_\w+):\s+session\s+(?P<action>\w+)\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)/(?P<src_port>\d+)->(?P<dst_ip>\d+\.\d+\.\d+\.\d+)/(?P<dst_port>\d+)\s+.*?(?:protocol-id\s+|\S+/\S+\s+)(?P<protocol>\d+|\w+)',
                "extracted_fields": {
                    "action": "$action",
                    "protocol": "$protocol",
                    "src_ip": "$src_ip",
                    "src_port": "$src_port",
                    "dst_ip": "$dst_ip",
                    "dst_port": "$dst_port",
                    "event_type": "$event_type",
                },
            },
        ],
        "signer_key_id": "dev_signing",
    },
    {
        "pack_id": "suricata_ids_v1.0.0",
        "source_type": "suricata_ids",
        "version": "1.0.0",
        "description": "Suricata and Snort IDS/IPS alert mapping pack",
        "parent_pack_id": "base_network_v1.0.0",
        "signatures": [
            {
                "name": "suricata_fast_alert",
                "pattern": r'\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<alert_msg>[^\[]+)\[\*\*\]\s+.*\{(?P<protocol>\w+)\}\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+)\s+->\s+(?P<dst_ip>\d+\.\d+\.\d+\.\d+):(?P<dst_port>\d+)',
                "extracted_fields": {
                    "action": "Refuse",
                    "protocol": "$protocol",
                    "src_ip": "$src_ip",
                    "src_port": "$src_port",
                    "dst_ip": "$dst_ip",
                    "dst_port": "$dst_port",
                    "signature_id": "$sid",
                    "alert_message": "$alert_msg",
                },
            },
        ],
        "signer_key_id": "dev_signing",
    },
    {
        "pack_id": "zeek_conn_v1.0.0",
        "source_type": "zeek_conn",
        "version": "1.0.0",
        "description": "Zeek (Bro) conn.log network monitor mapping pack",
        "parent_pack_id": "base_network_v1.0.0",
        "signatures": [
            {
                "name": "zeek_conn_record",
                "pattern": r'^(?P<ts>\d+(\.\d+)?)\s+(?P<uid>\S+)\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+(?P<src_port>\d+)\s+(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\s+(?P<dst_port>\d+)\s+(?P<protocol>tcp|udp|icmp)\s+(?P<service>\S+)\s+(?P<duration>\S+)\s+(?P<orig_bytes>\S+)\s+(?P<resp_bytes>\S+)\s+(?P<conn_state>\S+)',
                "extracted_fields": {
                    "action": "Traffic",
                    "protocol": "$protocol",
                    "src_ip": "$src_ip",
                    "src_port": "$src_port",
                    "dst_ip": "$dst_ip",
                    "dst_port": "$dst_port",
                    "conn_state": "$conn_state",
                    "service": "$service",
                },
            },
        ],
        "signer_key_id": "dev_signing",
    },
    {
        "pack_id": "linux_iptables_v1.0.0",
        "source_type": "linux_iptables",
        "version": "1.0.0",
        "description": "Linux Kernel Netfilter iptables and UFW firewall mapping pack",
        "parent_pack_id": "base_network_v1.0.0",
        "signatures": [
            {
                "name": "iptables_packet_log",
                "pattern": r'(?P<prefix>\[\w+\]|[A-Z_\-]+):\s+.*IN=(?P<in_if>\S*)\s+OUT=(?P<out_if>\S*)\s+.*SRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+DST=(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\s+.*PROTO=(?P<protocol>\w+)\s+SPT=(?P<src_port>\d+)\s+DPT=(?P<dst_port>\d+)',
                "extracted_fields": {
                    "action": "Deny",
                    "protocol": "$protocol",
                    "src_ip": "$src_ip",
                    "src_port": "$src_port",
                    "dst_ip": "$dst_ip",
                    "dst_port": "$dst_port",
                    "in_interface": "$in_if",
                    "out_interface": "$out_if",
                },
            },
        ],
        "signer_key_id": "dev_signing",
    },
    {
        "pack_id": "cef_perimeter_v1.0.0",
        "source_type": "cef_perimeter",
        "version": "1.0.0",
        "description": "ArcSight Common Event Format (CEF) Perimeter Gateway mapping pack",
        "parent_pack_id": "base_network_v1.0.0",
        "signatures": [
            {
                "name": "cef_firewall_event",
                "pattern": r'CEF:0\|(?P<vendor>[^\|]+)\|(?P<product>[^\|]+)\|(?P<version>[^\|]+)\|(?P<device_event_class_id>[^\|]+)\|(?P<name>[^\|]+)\|(?P<severity>[^\|]+)\|.*?src=(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+.*?dst=(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\s+.*?spt=(?P<src_port>\d+)\s+.*?dpt=(?P<dst_port>\d+)\s+.*?proto=(?P<proto>\w+)\s+.*?act=(?P<action>\w+)',
                "extracted_fields": {
                    "action": "$action",
                    "protocol": "$proto",
                    "src_ip": "$src_ip",
                    "src_port": "$src_port",
                    "dst_ip": "$dst_ip",
                    "dst_port": "$dst_port",
                    "vendor": "$vendor",
                    "product": "$product",
                },
            },
        ],
        "signer_key_id": "dev_signing",
    },
    {
        "pack_id": "leef_perimeter_v1.0.0",
        "source_type": "leef_perimeter",
        "version": "1.0.0",
        "description": "IBM QRadar Log Event Extended Format (LEEF) Perimeter mapping pack",
        "parent_pack_id": "base_network_v1.0.0",
        "signatures": [
            {
                "name": "leef_network_event",
                "pattern": r'LEEF:(?:1\.0|2\.0)\|(?P<vendor>[^\|]+)\|(?P<product>[^\|]+)\|(?P<version>[^\|]+)\|(?P<event_id>[^\|]+)\|.*?src=(?P<src_ip>\d+\.\d+\.\d+\.\d+).*?dst=(?P<dst_ip>\d+\.\d+\.\d+\.\d+).*?srcPort=(?P<src_port>\d+).*?dstPort=(?P<dst_port>\d+).*?proto=(?P<proto>\w+).*?(?:act|action)=(?P<action>\w+)',
                "extracted_fields": {
                    "action": "$action",
                    "protocol": "$proto",
                    "src_ip": "$src_ip",
                    "src_port": "$src_port",
                    "dst_ip": "$dst_ip",
                    "dst_port": "$dst_port",
                    "vendor": "$vendor",
                    "product": "$product",
                },
            },
        ],
        "signer_key_id": "dev_signing",
    },
    {
        "pack_id": "syslog_rfc5424_v1.0.0",
        "source_type": "syslog_rfc5424",
        "version": "1.0.0",
        "description": "IETF RFC5424 Structured Perimeter Appliance mapping pack",
        "parent_pack_id": "base_network_v1.0.0",
        "signatures": [
            {
                "name": "rfc5424_perimeter_packet",
                "pattern": r'^<\d+>1\s+(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+(?P<app>\S+)\s+(?P<proc_id>\S+)\s+(?P<msg_id>\S+)\s+(?P<sd>\[.*?\]|-)\s+(?P<action>ALLOW|DENY|DROP|PERMIT)\s+(?P<protocol>TCP|UDP|ICMP)\s+src=(?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+)\s+dst=(?P<dst_ip>\d+\.\d+\.\d+\.\d+):(?P<dst_port>\d+)',
                "extracted_fields": {
                    "action": "$action",
                    "protocol": "$protocol",
                    "src_ip": "$src_ip",
                    "src_port": "$src_port",
                    "dst_ip": "$dst_ip",
                    "dst_port": "$dst_port",
                    "timestamp": "$timestamp",
                },
            },
        ],
        "signer_key_id": "dev_signing",
    },
    {
        "pack_id": "sophos_xg_v1.0.0",
        "source_type": "sophos_xg",
        "version": "1.0.0",
        "description": "Sophos XG / Cyberoam Next-Gen Firewall perimeter key-value log mapping pack",
        "parent_pack_id": "base_network_v1.0.0",
        "signatures": [
            {
                "name": "sophos_xg_firewall_rule",
                "pattern": r'Time="(?P<time>[^"]+)"\s+Log comp="(?P<log_comp>[^"]+)"\s+Log subtype="(?P<action>[^"]+)"(?:.*?)Src IP="(?P<src_ip>\d+\.\d+\.\d+\.\d+)"\s+Dst IP="(?P<dst_ip>\d+\.\d+\.\d+\.\d+)"\s+Src port="(?P<src_port>\d+)"\s+Dst port="(?P<dst_port>\d+)"\s+protocol="(?P<protocol>[^"]+)"',
                "extracted_fields": {
                    "time": "$time",
                    "action": "$action",
                    "src_ip": "$src_ip",
                    "src_port": "$src_port",
                    "dst_ip": "$dst_ip",
                    "dst_port": "$dst_port",
                    "protocol": "$protocol",
                    "log_comp": "$log_comp",
                },
            },
            {
                "name": "sophos_xg_general_traffic",
                "pattern": r'.*Src IP="(?P<src_ip>\d+\.\d+\.\d+\.\d+)"\s+Dst IP="(?P<dst_ip>\d+\.\d+\.\d+\.\d+)"\s+Src port="(?P<src_port>\d+)"\s+Dst port="(?P<dst_port>\d+)"\s+protocol="(?P<protocol>[^"]+)"(?:.*?)Log subtype="(?P<action>[^"]+)"',
                "extracted_fields": {
                    "action": "$action",
                    "src_ip": "$src_ip",
                    "src_port": "$src_port",
                    "dst_ip": "$dst_ip",
                    "dst_port": "$dst_port",
                    "protocol": "$protocol",
                },
            },
        ],
        "signer_key_id": "dev_signing",
    },
]


def main() -> None:
    if not PRIV_KEY_PATH.exists():
        print(f"Error: signing key not found at {PRIV_KEY_PATH}", file=sys.stderr)
        sys.exit(1)

    priv_key_pem = PRIV_KEY_PATH.read_bytes()
    pub_key_pem = PUB_KEY_PATH.read_bytes()

    VENDORS_DIR.mkdir(parents=True, exist_ok=True)

    print("Generating & signing production perimeter packs...")
    for pack in PACKS:
        pack_id = pack["pack_id"]
        # Sign the pack dictionary
        sig = sign_pack(pack, priv_key_pem)
        pack["signature"] = sig

        # Verify before writing
        if not verify_pack_signature(pack, pub_key_pem):
            print(f"FAILED self-verification for {pack_id}!", file=sys.stderr)
            sys.exit(1)

        out_path = VENDORS_DIR / f"{pack_id}.yaml"
        with open(out_path, "w", encoding="utf-8") as f:
            yaml.dump(pack, f, sort_keys=False, default_flow_style=False)
        print(f"  [+] {pack_id}.yaml successfully signed & written ({len(pack['signatures'])} signatures)")

    print(f"\nAll {len(PACKS)} perimeter packs successfully signed and verified.")


if __name__ == "__main__":
    main()
