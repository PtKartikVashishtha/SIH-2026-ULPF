from dataclasses import dataclass, field
from re import Pattern


@dataclass(frozen=True)
class SignatureDefinition:
    name: str
    pattern: str
    extracted_fields: dict[str, str] = field(default_factory=dict)
    description: str = ""


@dataclass
class PackDefinition:
    pack_id: str
    source_type: str
    version: str
    description: str = ""
    parent_pack_id: str | None = None
    signatures: list[SignatureDefinition] = field(default_factory=list)
    signature: str = ""
    signer_key_id: str = "dev_signing"


@dataclass(frozen=True)
class CompiledSignature:
    name: str
    regex: Pattern[str]
    extracted_fields: dict[str, str]
    source_type: str
    parser_version: str


@dataclass(frozen=True)
class CompiledPack:
    pack_id: str
    source_type: str
    version: str
    signatures: tuple[CompiledSignature, ...]
    parent_pack_id: str | None = None
    pack_yaml_hash: str = ""
    signature: str = ""
    signer_key_id: str = "dev_signing"
