"""
Draft Pack Generator for ULPF Cold Path (M6).

Converts mined Drain log clusters and analyst-confirmed semantic mappings
into valid YAML mapping packs and automated test fixtures ready for hot-reload.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pipeline_svc.coldpath.drain import LogCluster


RE_IP_PORT = re.compile(
    r"^(?:(?P<iface>[a-zA-Z0-9_\-]+)[:/])?(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[:/(](?P<port>\d{1,5})\)?$"
)
RE_IP_ONLY = re.compile(
    r"^(?:(?P<iface>[a-zA-Z0-9_\-]+)[:/])?(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
)


RE_KV_PAIRS = re.compile(
    r'\b([a-zA-Z_][a-zA-Z0-9_\-]*(?:\s+[a-zA-Z_][a-zA-Z0-9_\-]*)*)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s]+))'
)


def template_to_regex(template: str, sample_log: str | None = None) -> str:
    r"""
    Converts a Drain template with `<*>` wildcards into a named capture regex.
    Uses sample_log tokens and syntactic inspection to extract semantic parameter names
    such as src_ip, dst_ip, ports, and key-values rather than generic var_N.
    """
    if sample_log:
        kv_pairs = RE_KV_PAIRS.findall(sample_log)
        tokens = sample_log.split()
        if len(kv_pairs) >= 4 or (len(kv_pairs) >= 2 and len(kv_pairs) / max(1, len(tokens)) >= 0.4):
            parts = []
            for k, _q1, _q2, _unq in kv_pairs:
                k_esc = re.escape(k)
                k_clean = k.strip().lower()
                if "src" in k_clean and ("ip" in k_clean or "addr" in k_clean or "host" in k_clean):
                    var_name = "src_ip"
                elif ("dst" in k_clean or "dest" in k_clean) and (
                    "ip" in k_clean or "addr" in k_clean or "host" in k_clean
                ):
                    var_name = "dst_ip"
                elif "src" in k_clean and ("port" in k_clean or "spt" in k_clean):
                    var_name = "src_port"
                elif ("dst" in k_clean or "dest" in k_clean) and ("port" in k_clean or "dport" in k_clean):
                    var_name = "dst_port"
                elif k_clean in ("proto", "protocol"):
                    var_name = "protocol"
                elif k_clean in ("action", "subtype", "log subtype", "status", "act"):
                    var_name = "action"
                elif k_clean in ("time", "timestamp", "date", "eventtime"):
                    var_name = "time"
                else:
                    var_name = re.sub(r"[^a-zA-Z0-9_]+", "_", k_clean)
                if var_name and var_name[0].isdigit():
                    var_name = f"var_{var_name}"
                parts.append(k_esc + r'="?(?P<' + var_name + r'>[^"\'`,\s;]+(?:\s+[^"\'`,\s;]+)*)"?')
            return r".*?" + r".*?".join(parts) + r".*"

    template_tokens = template.split()
    sample_tokens: list[str] = sample_log.split() if sample_log else []

    parts: list[str] = []
    ip_count = 0

    for idx, t_tok in enumerate(template_tokens):
        s_tok = sample_tokens[idx] if idx < len(sample_tokens) else ""
        prev_tok = sample_tokens[idx - 1].lower().rstrip(":") if idx > 0 and idx - 1 < len(sample_tokens) else ""

        if idx == 0 and t_tok in ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"):
            parts.append(r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)")
            continue

        if t_tok == "<*>":
            if "=" in s_tok and not s_tok.startswith("="):
                key, _ = s_tok.split("=", 1)
                clean_k = re.sub(r"[^a-zA-Z0-9_]", "_", key)
                if clean_k and clean_k[0].isdigit():
                    clean_k = f"var_{clean_k}"
                parts.append(re.escape(key) + r"=(?P<" + clean_k + r">\S+)")
                continue

            clean_s = s_tok.strip("(),;\"'")
            m_ipport = RE_IP_PORT.match(clean_s)
            if m_ipport:
                is_src = prev_tok in ("from", "src", "source", "for", "client") or (
                    ip_count == 0 and prev_tok not in ("to", "dst", "dest")
                )
                prefix = "src" if is_src else "dst"
                parts.append(r"(?P<" + prefix + r"_ip>\d+\.\d+\.\d+\.\d+)[:/(](?P<" + prefix + r"_port>\d+)\)?")
                ip_count += 1
                continue

            m_ip = RE_IP_ONLY.match(clean_s)
            if m_ip:
                is_src = prev_tok in ("from", "src", "source", "for", "client") or (
                    ip_count == 0 and prev_tok not in ("to", "dst", "dest")
                )
                prefix = "src" if is_src else "dst"
                parts.append(r"(?P<" + prefix + r"_ip>\d+\.\d+\.\d+\.\d+)")
                ip_count += 1
                continue

            if prev_tok in ("port", "spt", "dport") and clean_s.isdigit():
                prefix = "src" if prev_tok in ("port", "spt") and ip_count > 0 else "dst"
                parts.append(r"(?P<" + prefix + r"_port>\d+)")
                continue

            parts.append(r"(?P<var_" + str(len(parts) + 1) + r">\S+)")
        else:
            parts.append(re.escape(t_tok))

    return "^" + r"\s+".join(parts) + "$"


class DraftPackGenerator:
    """Generates structured YAML mapping packs and test fixtures from clusters."""

    def __init__(self, base_pack_id: str | None = None) -> None:
        self.base_pack_id = base_pack_id

    def generate_pack_dict(
        self,
        cluster: LogCluster,
        confirmed_mapping: dict[str, str],
        source_type: str = "cisco_asa",
        version: str = "1.0.0",
    ) -> dict[str, Any]:
        """Creates a complete mapping pack dictionary matching the pack compiler schema."""
        pack_id = f"{source_type}_{cluster.cluster_id.replace('-', '_')}_v{version}"
        sample_log = cluster.sample_logs[0] if cluster.sample_logs else None
        regex_pattern = template_to_regex(cluster.template, sample_log)

        # Merge confirmed mapping with any newly identified named capture groups
        named_groups = re.findall(r"\(\?P<([a-zA-Z0-9_]+)>", regex_pattern)
        merged_mapping = dict(confirmed_mapping)
        for g in named_groups:
            if g not in merged_mapping:
                merged_mapping[g] = f"${g}"

        pack_dict: dict[str, Any] = {
            "pack_id": pack_id,
            "version": version,
            "source_type": source_type,
            "description": f"Auto-generated mapping pack from cluster {cluster.cluster_id}",
            "signatures": [
                {
                    "name": f"{source_type}_{cluster.cluster_id.replace('-', '_')}",
                    "pattern": regex_pattern,
                    "extracted_fields": merged_mapping,
                }
            ],
            "signer_key_id": "dev_signing",
        }

        if self.base_pack_id:
            pack_dict["parent_pack_id"] = self.base_pack_id

        return pack_dict

    def generate_fixture_record(
        self,
        pack_id: str,
        sample_raw: str,
        expected_ocsf: dict[str, Any],
    ) -> dict[str, Any]:
        """Builds a test fixture record suitable for SQLite test_fixtures table."""
        return {
            "pack_id": pack_id,
            "sample_raw_pointer": f"raw_store://fixtures/{pack_id}",
            "sample_raw_text": sample_raw,
            "expected_ocsf_json": json.dumps(expected_ocsf, default=str),
        }
