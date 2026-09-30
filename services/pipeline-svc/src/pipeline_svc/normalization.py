import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from ulpf_contracts import ExtractionEnvelope, OcsfNetworkActivityV1

from .db import SqlitePipelineRepository


class EventBus(Protocol):
    def publish(self, topic: str, message: dict[str, Any]) -> None: ...


# ─── Layer 2 Canonicalizers ──────────────────────────────────────────────────

PROTO_MAP: dict[str, tuple[int, str]] = {
    "tcp": (6, "tcp"),
    "udp": (17, "udp"),
    "icmp": (1, "icmp"),
    "gre": (47, "gre"),
    "esp": (50, "esp"),
    "ah": (51, "ah"),
    "sctp": (132, "sctp"),
}

ACTIVITY_MAP: dict[str, tuple[int, str]] = {
    "allow": (1, "Open"),
    "permit": (1, "Open"),
    "permitted": (1, "Open"),
    "accept": (1, "Open"),
    "accepted": (1, "Open"),
    "open": (1, "Open"),
    "close": (2, "Close"),
    "teardown": (2, "Close"),
    "end": (2, "Close"),
    "reset": (3, "Reset"),
    "fail": (4, "Fail"),
    "failure": (4, "Fail"),
    "deny": (5, "Refuse"),
    "denied": (5, "Refuse"),
    "block": (5, "Refuse"),
    "blocked": (5, "Refuse"),
    "drop": (5, "Refuse"),
    "dropped": (5, "Refuse"),
    "reject": (5, "Refuse"),
    "rejected": (5, "Refuse"),
    "refuse": (5, "Refuse"),
    "traffic": (6, "Traffic"),
}


def canonicalize_ip(ip_str: str | None) -> str | None:
    """Canonicalize IPv4 and IPv6 addresses.

    - Strips leading zeros on IPv4 octets (e.g. 192.168.001.001 -> 192.168.1.1).
    - Standardizes IPv6 to lowercase compressed form per RFC 5952.
    - Returns None if invalid.
    """
    if not ip_str or not isinstance(ip_str, str):
        return None
    cleaned = ip_str.strip()
    if not cleaned:
        return None

    # Handle IPv4 with possible leading zeroes:
    if "." in cleaned and ":" not in cleaned:
        parts = cleaned.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            try:
                # Strip leading zeroes, but keep single 0
                stripped_parts = [str(int(p)) for p in parts]
                if any(int(p) > 255 for p in stripped_parts):
                    return None
                reconstructed = ".".join(stripped_parts)
                addr4 = ipaddress.IPv4Address(reconstructed)
                return str(addr4)
            except (ValueError, TypeError):
                return None
        return None

    # Handle IPv6
    try:
        addr6 = ipaddress.IPv6Address(cleaned)
        return addr6.compressed.lower()
    except (ValueError, TypeError):
        return None


def canonicalize_port(port_val: int | str | None) -> int | None:
    """Validate and canonicalize port numbers to integer range [0, 65535]."""
    if port_val is None:
        return None
    try:
        p = int(str(port_val).strip())
        if 0 <= p <= 65535:
            return p
        return None
    except (ValueError, TypeError):
        return None


def canonicalize_timestamp(ts_val: int | float | str | None) -> int:
    """Convert timestamp representations to epoch milliseconds UTC.

    Supports:
    - Numeric timestamps (seconds, milliseconds, microseconds)
    - ISO-8601 strings (UTC or with timezone offsets)
    - Syslog BSD timestamps (e.g. 'Sep 25 09:12:44' or 'Sep 25 2026 09:12:44')
    Raises ValueError on malformed timestamps.
    """
    if ts_val is None:
        return int(datetime.now(UTC).timestamp() * 1000)

    if isinstance(ts_val, (int, float)):
        val = float(ts_val)
        if val < 0:
            raise ValueError(f"Timestamp cannot be negative: {ts_val}")
        if val < 1e11:  # seconds (e.g. 1.7e9)
            return int(val * 1000)
        if val < 1e14:  # milliseconds (e.g. 1.7e12)
            return int(val)
        return int(val / 1000)  # microseconds or nanoseconds

    ts_str = str(ts_val).strip()
    if not ts_str:
        raise ValueError("Empty timestamp string")

    # Numeric string
    if re.match(r"^\d+(\.\d+)?$", ts_str):
        return canonicalize_timestamp(float(ts_str))

    # ISO-8601
    try:
        # Standardize Z to +00:00 for older/standard parsers if needed
        clean_iso = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return int(dt.timestamp() * 1000)
    except ValueError:
        pass

    # Syslog BSD formats
    # With year: 'Sep 25 2026 09:12:44'
    for fmt in ("%b %d %Y %H:%M:%S", "%b %d %Y %H:%M:%S.%f"):
        try:
            dt = datetime.strptime(ts_str, fmt).replace(tzinfo=UTC)
            return int(dt.timestamp() * 1000)
        except ValueError:
            pass

    # Without year: 'Sep 25 09:12:44' -> prepend current year (2026) to avoid ambiguous leap-day warning
    current_year = datetime.now(UTC).year
    for fmt in ("%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
        try:
            dt = datetime.strptime(f"{current_year} {ts_str}", f"%Y {fmt}").replace(tzinfo=UTC)
            return int(dt.timestamp() * 1000)
        except ValueError:
            pass

    raise ValueError(f"Unrecognized or invalid timestamp format: {ts_val}")


def canonicalize_activity(action: str | None) -> tuple[int, str]:
    """Map action to OCSF 4001 activity_id and activity_name.

    Fallback to (99, 'Other') on unrecognized action.
    """
    if not action:
        return (99, "Other")
    cleaned = action.strip().lower()
    return ACTIVITY_MAP.get(cleaned, (99, "Other"))


def canonicalize_protocol(proto: str | None) -> tuple[int, str]:
    """Map protocol string or number to (protocol_num, protocol_name)."""
    if not proto:
        return (99, "unknown")
    cleaned = proto.strip().lower()
    if cleaned in PROTO_MAP:
        return PROTO_MAP[cleaned]
    if cleaned.isdigit():
        num = int(cleaned)
        for _, v in PROTO_MAP.items():
            if v[0] == num:
                return v
        return (num, str(num))
    return (99, cleaned)


# ─── Layer 1 Crosswalk & Layer 3 Assembly ───────────────────────────────────

VENDOR_PRODUCT_MAP: dict[str, tuple[str, str]] = {
    "cisco_asa": ("Cisco", "ASA Firewall"),
    "palo_alto_fw": ("Palo Alto Networks", "PAN-OS Firewall"),
    "fortinet_fortigate": ("Fortinet", "FortiGate"),
    "nginx_access": ("F5 NGINX", "NGINX Web Server"),
    "windows_event": ("Microsoft", "Windows Event Log"),
}


@dataclass
class NormalizationResult:
    ocsf_event: OcsfNetworkActivityV1 | None
    schema_valid: bool
    validation_errors: list[str] | None
    raw_dict: dict[str, Any]


def crosswalk_to_ocsf_dict(
    envelope: ExtractionEnvelope,
    raw_data_ptr: str | None = None,
    ingestion_time: str | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Perform Layer 1 crosswalk and Layer 2 canonicalization into a raw dictionary."""
    fields = envelope.extracted_fields
    errors: list[str] = []

    # 1. Endpoints
    src_ip = canonicalize_ip(fields.get("src_ip") or fields.get("src") or fields.get("source_ip"))
    src_port = canonicalize_port(fields.get("src_port") or fields.get("sport"))
    dst_ip = canonicalize_ip(fields.get("dst_ip") or fields.get("dst") or fields.get("dest_ip"))
    dst_port = canonicalize_port(fields.get("dst_port") or fields.get("dport"))

    src_endpoint: dict[str, Any] = {}
    if src_ip is not None:
        src_endpoint["ip"] = src_ip
    if src_port is not None:
        src_endpoint["port"] = src_port
    if "src_host" in fields:
        src_endpoint["hostname"] = fields["src_host"]

    dst_endpoint: dict[str, Any] = {}
    if dst_ip is not None:
        dst_endpoint["ip"] = dst_ip
    if dst_port is not None:
        dst_endpoint["port"] = dst_port
    if "dst_host" in fields:
        dst_endpoint["hostname"] = fields["dst_host"]

    # 2. Connection Info
    proto_str = fields.get("protocol") or fields.get("proto")
    proto_num, proto_name = canonicalize_protocol(proto_str)
    connection_info: dict[str, Any] = {
        "protocol_num": proto_num,
        "protocol_name": proto_name,
    }

    # 3. Activity & Severity
    act_id, act_name = canonicalize_activity(fields.get("action") or fields.get("disposition"))
    if act_id == 5:  # Refuse / Deny
        severity_id = 4
    elif act_id == 1:  # Open / Allow
        severity_id = 1
    else:
        severity_id = 2

    # 4. Timestamp
    raw_ts = fields.get("timestamp") or fields.get("time") or fields.get("datetime") or ingestion_time
    try:
        event_time = canonicalize_timestamp(raw_ts)
    except ValueError as e:
        errors.append(f"Invalid timestamp: {e}")
        event_time = 0

    # 5. Metadata & Product
    st = envelope.source_type
    vendor_name, prod_name = VENDOR_PRODUCT_MAP.get(st, (st.capitalize(), "Network Device"))
    product = {"vendor_name": vendor_name, "name": prod_name}

    uid_str = str(envelope.lineage_id)
    metadata = {
        "version": "1.2.0",
        "uid": uid_str,
        "product": product,
    }

    # 6. Confidence scores
    conf_dict: dict[str, float] = {}
    if envelope.confidence_scores:
        for k, v in envelope.confidence_scores.items():
            conf_dict[k] = float(v)

    raw_ptr = raw_data_ptr or "raw_store://chunk_unknown/offset_0"

    event_dict: dict[str, Any] = {
        "activity_id": act_id,
        "activity_name": act_name,
        "category_uid": 4,
        "class_uid": 4001,
        "class_name": "Network Activity",
        "severity_id": severity_id,
        "time": event_time,
        "src_endpoint": src_endpoint,
        "dst_endpoint": dst_endpoint,
        "connection_info": connection_info,
        "metadata": metadata,
        "raw_data": raw_ptr,
        "_confidence": conf_dict,
        "_lineage_id": uid_str,
    }

    return event_dict, errors


def assemble_ocsf_event(
    envelope: ExtractionEnvelope,
    raw_data_ptr: str | None = None,
    ingestion_time: str | None = None,
) -> NormalizationResult:
    """Assemble and validate OcsfNetworkActivityV1 from an ExtractionEnvelope."""
    event_dict, errors = crosswalk_to_ocsf_dict(envelope, raw_data_ptr=raw_data_ptr, ingestion_time=ingestion_time)

    if errors:
        return NormalizationResult(
            ocsf_event=None,
            schema_valid=False,
            validation_errors=errors,
            raw_dict=event_dict,
        )

    try:
        # Validate using Pydantic model
        ocsf_obj = OcsfNetworkActivityV1.model_validate(event_dict)

        # Invariant check: metadata.uid == _lineage_id
        if str(ocsf_obj.metadata.uid) != str(ocsf_obj.field_lineage_id):
            errors.append("Invariant violated: metadata.uid must equal _lineage_id")
            return NormalizationResult(
                ocsf_event=None,
                schema_valid=False,
                validation_errors=errors,
                raw_dict=event_dict,
            )

        return NormalizationResult(
            ocsf_event=ocsf_obj,
            schema_valid=True,
            validation_errors=None,
            raw_dict=event_dict,
        )
    except Exception as err:
        errors.append(f"OCSF schema validation error: {err}")
        return NormalizationResult(
            ocsf_event=None,
            schema_valid=False,
            validation_errors=errors,
            raw_dict=event_dict,
        )


def normalize_and_record(
    envelope: ExtractionEnvelope,
    extraction_id: int,
    repo: SqlitePipelineRepository | None = None,
    bus: EventBus | None = None,
    raw_data_ptr: str | None = None,
    ingestion_time: str | None = None,
) -> tuple[NormalizationResult, int]:
    """Execute full normalization pipeline: assembly, validation, persistence, and bus publish."""
    result = assemble_ocsf_event(envelope, raw_data_ptr=raw_data_ptr, ingestion_time=ingestion_time)

    published = False
    if result.schema_valid and result.ocsf_event is not None and bus is not None:
        try:
            event_payload = result.ocsf_event.model_dump(mode="json", by_alias=True)
            bus.publish("ulpf.ocsf.events.v1", event_payload)
            published = True
        except Exception:
            published = False

    norm_id = 0
    if repo is not None:
        norm_id = repo.record_normalization(
            lineage_id=str(envelope.lineage_id),
            extraction_id=extraction_id,
            ocsf_class_uid=4001,
            ocsf_event_json=result.raw_dict,
            schema_valid=result.schema_valid,
            validation_errors=result.validation_errors,
            published_to_bus=published,
        )

    return result, norm_id

