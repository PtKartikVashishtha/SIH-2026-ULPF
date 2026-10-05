from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .compiler import CompilationError, CyclicInheritanceError, compile_pack, parse_pack_dict
from .crypto import compute_pack_hash, verify_pack_signature
from .models import CompiledPack, CompiledSignature


@dataclass(frozen=True)
class RegistrySnapshot:
    packs: dict[str, CompiledPack]
    signatures: tuple[CompiledSignature, ...]
    source_type_to_pack: dict[str, CompiledPack]


class PackRegistry:
    def __init__(self, public_key_pem: bytes | str) -> None:
        self._public_key_pem = public_key_pem
        self._snapshot = RegistrySnapshot(packs={}, signatures=(), source_type_to_pack={})
        self._raw_pack_defs: dict[str, Any] = {}
        self._history: dict[str, list[CompiledPack]] = {}
        self._quarantined: dict[str, str] = {}

    @property
    def snapshot(self) -> RegistrySnapshot:
        return self._snapshot

    def get_quarantined(self) -> dict[str, str]:
        return dict(self._quarantined)

    def load_pack(self, pack_yaml_str_or_dict: str | dict[str, Any]) -> bool:
        if isinstance(pack_yaml_str_or_dict, str):
            data = yaml.safe_load(pack_yaml_str_or_dict)
        else:
            data = pack_yaml_str_or_dict

        pack_id = data.get("pack_id", "unknown")

        if not verify_pack_signature(data, self._public_key_pem):
            self._quarantined[pack_id] = "Invalid or missing Ed25519 cryptographic signature"
            return False

        pack_def = parse_pack_dict(data)
        temp_defs = {**self._raw_pack_defs, pack_id: pack_def}

        try:
            pack_hash = compute_pack_hash(data)
            compiled = compile_pack(pack_def, temp_defs, pack_yaml_hash=pack_hash)
        except (CompilationError, CyclicInheritanceError) as err:
            self._quarantined[pack_id] = f"Compilation failed: {err}"
            return False

        self._quarantined.pop(pack_id, None)
        self._raw_pack_defs[pack_id] = pack_def

        st = compiled.source_type
        if st not in self._history:
            self._history[st] = []
        if st in self._snapshot.source_type_to_pack:
            self._history[st].append(self._snapshot.source_type_to_pack[st])

        new_packs = dict(self._snapshot.packs)
        new_packs[pack_id] = compiled

        new_st_map = dict(self._snapshot.source_type_to_pack)
        new_st_map[st] = compiled

        new_sigs: list[CompiledSignature] = []
        for p in new_packs.values():
            new_sigs.extend(p.signatures)

        self._snapshot = RegistrySnapshot(packs=new_packs, signatures=tuple(new_sigs), source_type_to_pack=new_st_map)
        return True

    def rollback(self, source_type: str) -> bool:
        history_stack = self._history.get(source_type, [])
        if not history_stack:
            return False

        prior_pack = history_stack.pop()
        new_packs = dict(self._snapshot.packs)
        new_packs[prior_pack.pack_id] = prior_pack

        new_st_map = dict(self._snapshot.source_type_to_pack)
        new_st_map[source_type] = prior_pack

        new_sigs: list[CompiledSignature] = []
        for p in new_packs.values():
            new_sigs.extend(p.signatures)

        self._snapshot = RegistrySnapshot(packs=new_packs, signatures=tuple(new_sigs), source_type_to_pack=new_st_map)
        return True

    def load_file(self, file_path: str | Path) -> bool:
        p = Path(file_path)
        if not p.is_file():
            return False
        content = p.read_text(encoding="utf-8")
        return self.load_pack(content)

    def reconcile_sweep(self, packs_dir: str | Path) -> dict[str, bool]:
        root = Path(packs_dir)
        if not root.is_dir():
            return {}

        yaml_files = sorted(list(root.rglob("*.yaml")) + list(root.rglob("*.yml")))
        results: dict[str, bool] = {}

        parsed_candidates: dict[str, dict[str, Any]] = {}
        for yf in yaml_files:
            try:
                data = yaml.safe_load(yf.read_text(encoding="utf-8"))
            except Exception as e:
                self._quarantined[yf.name] = f"YAML syntax error: {e}"
                results[yf.name] = False
                continue

            if not isinstance(data, dict):
                self._quarantined[yf.name] = "YAML is not a mapping"
                results[yf.name] = False
                continue

            pack_id = data.get("pack_id", yf.name)
            if not data.get("signature"):
                sig_candidate = yf.with_suffix(yf.suffix + ".sig")
                if sig_candidate.is_file():
                    data["signature"] = sig_candidate.read_text(encoding="utf-8").strip()

            if not verify_pack_signature(data, self._public_key_pem):
                self._quarantined[pack_id] = "Invalid or missing Ed25519 cryptographic signature"
                results[pack_id] = False
                continue

            parsed_candidates[pack_id] = data

        remaining = dict(parsed_candidates)
        progress = True
        while remaining and progress:
            progress = False
            for pid, data in list(remaining.items()):
                extends_id = data.get("parent_pack_id") or data.get("extends")
                if not extends_id or extends_id in self._raw_pack_defs:
                    success = self.load_pack(data)
                    results[pid] = success
                    del remaining[pid]
                    progress = True

        for pid, data in remaining.items():
            dep = data.get("parent_pack_id") or data.get("extends")
            self._quarantined[pid] = f"Unresolved or cyclic dependency on parent='{dep}'"
            results[pid] = False

        return results
