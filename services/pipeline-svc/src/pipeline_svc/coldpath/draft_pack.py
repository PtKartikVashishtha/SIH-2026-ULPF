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


def template_to_regex(template: str, sample_log: str | None = None) -> str:
    r"""
    Converts a Drain template with `<*>` wildcards into a named capture regex.
    Uses sample_log tokens to extract semantic parameter names when key-value patterns exist.
    """
    template_tokens = template.split()
    sample_tokens = sample_log.split() if sample_log else []

    parts: list[str] = []
    for idx, t_tok in enumerate(template_tokens):
        s_tok = sample_tokens[idx] if idx < len(sample_tokens) else ""
        if t_tok == "<*>":
            if "=" in s_tok:
                key, _ = s_tok.split("=", 1)
                clean_k = re.sub(r"[^a-zA-Z0-9_]", "_", key)
                parts.append(re.escape(key) + r"=(?P<" + clean_k + r">\S+)")
            elif "/" in s_tok and ":" in s_tok:
                parts.append(r"(?P<endpoint_" + str(len(parts) + 1) + r">\S+)")
            else:
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

        pack_dict: dict[str, Any] = {
            "pack_id": pack_id,
            "version": version,
            "source_type": source_type,
            "description": f"Auto-generated mapping pack from cluster {cluster.cluster_id}",
            "signatures": [
                {
                    "name": f"{source_type}_{cluster.cluster_id.replace('-', '_')}",
                    "pattern": regex_pattern,
                    "extracted_fields": confirmed_mapping,
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
