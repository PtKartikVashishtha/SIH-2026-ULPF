import re
from typing import Any

from .models import CompiledPack, CompiledSignature, PackDefinition, SignatureDefinition


class CyclicInheritanceError(Exception):
    pass


class CompilationError(Exception):
    pass


def parse_pack_dict(data: dict[str, Any]) -> PackDefinition:
    pack_id = data["pack_id"]
    source_type = data["source_type"]
    version = str(data["version"])
    parent_pack_id = data.get("parent_pack_id")
    description = data.get("description", "")
    signature = data.get("signature", "")
    signer_key_id = data.get("signer_key_id", "dev_signing")

    signatures: list[SignatureDefinition] = []
    for sig_data in data.get("signatures", []):
        signatures.append(
            SignatureDefinition(
                name=sig_data["name"],
                pattern=sig_data["pattern"],
                extracted_fields=sig_data.get("extracted_fields", {}),
                description=sig_data.get("description", ""),
            )
        )

    return PackDefinition(
        pack_id=pack_id,
        source_type=source_type,
        version=version,
        description=description,
        parent_pack_id=parent_pack_id,
        signatures=signatures,
        signature=signature,
        signer_key_id=signer_key_id,
    )


def resolve_inheritance(pack: PackDefinition, all_packs: dict[str, PackDefinition]) -> list[SignatureDefinition]:
    visited = set()
    chain: list[PackDefinition] = []

    curr: PackDefinition | None = pack
    while curr:
        if curr.pack_id in visited:
            raise CyclicInheritanceError(f"Cycle detected in pack inheritance: {curr.pack_id}")
        visited.add(curr.pack_id)
        chain.append(curr)
        if curr.parent_pack_id:
            curr = all_packs.get(curr.parent_pack_id)
            if not curr:
                break
        else:
            break

    merged_signatures: dict[str, SignatureDefinition] = {}
    for ancestor in reversed(chain):
        for sig in ancestor.signatures:
            merged_signatures[sig.name] = sig

    return list(merged_signatures.values())


def compile_pack(
    pack: PackDefinition, all_packs: dict[str, PackDefinition] | None = None, pack_yaml_hash: str = ""
) -> CompiledPack:
    if all_packs is None:
        all_packs = {pack.pack_id: pack}

    effective_signatures = resolve_inheritance(pack, all_packs)

    compiled_sigs: list[CompiledSignature] = []
    for sig in effective_signatures:
        try:
            pattern = re.compile(sig.pattern)
        except re.error as err:
            raise CompilationError(f"Failed to compile regex '{sig.pattern}' in {pack.pack_id}: {err}") from err

        compiled_sigs.append(
            CompiledSignature(
                name=sig.name,
                regex=pattern,
                extracted_fields=dict(sig.extracted_fields),
                source_type=pack.source_type,
                parser_version=pack.version,
            )
        )

    return CompiledPack(
        pack_id=pack.pack_id,
        source_type=pack.source_type,
        version=pack.version,
        signatures=tuple(compiled_sigs),
        parent_pack_id=pack.parent_pack_id,
        pack_yaml_hash=pack_yaml_hash,
        signature=pack.signature,
        signer_key_id=pack.signer_key_id,
    )
