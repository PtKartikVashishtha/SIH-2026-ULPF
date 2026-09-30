import pytest

from pipeline_svc.compiler import (
    CompilationError,
    CyclicInheritanceError,
    compile_pack,
    parse_pack_dict,
    resolve_inheritance,
)


def test_compiler_inheritance_and_override() -> None:
    base = parse_pack_dict(
        {
            "pack_id": "base_v1",
            "source_type": "base",
            "version": "1.0.0",
            "signatures": [
                {"name": "sig1", "pattern": "base-pattern", "extracted_fields": {"src": "base_src"}},
                {"name": "sig2", "pattern": "base-pattern-2", "extracted_fields": {"val": "100"}},
            ],
        }
    )

    child = parse_pack_dict(
        {
            "pack_id": "child_v1",
            "source_type": "child",
            "version": "1.0.0",
            "parent_pack_id": "base_v1",
            "signatures": [
                {"name": "sig1", "pattern": "child-override-pattern", "extracted_fields": {"src": "child_src"}},
                {"name": "sig3", "pattern": "child-sig3", "extracted_fields": {"dst": "target"}},
            ],
        }
    )

    all_packs = {"base_v1": base, "child_v1": child}
    compiled = compile_pack(child, all_packs)

    assert len(compiled.signatures) == 3
    sig_map = {s.name: s for s in compiled.signatures}

    assert sig_map["sig1"].regex.pattern == "child-override-pattern"
    assert sig_map["sig1"].extracted_fields["src"] == "child_src"
    assert sig_map["sig2"].regex.pattern == "base-pattern-2"
    assert sig_map["sig3"].regex.pattern == "child-sig3"


EMPTY_SIGS: list[dict[str, object]] = []
EMPTY_FIELDS: dict[str, str] = {}


def test_compiler_rejects_cyclic_inheritance() -> None:
    pack_a = parse_pack_dict(
        {"pack_id": "pack_a", "source_type": "a", "version": "1.0.0", "parent_pack_id": "pack_b", "signatures": EMPTY_SIGS}
    )
    pack_b = parse_pack_dict(
        {"pack_id": "pack_b", "source_type": "b", "version": "1.0.0", "parent_pack_id": "pack_a", "signatures": EMPTY_SIGS}
    )

    all_packs = {"pack_a": pack_a, "pack_b": pack_b}

    with pytest.raises(CyclicInheritanceError):
        resolve_inheritance(pack_a, all_packs)


def test_compiler_invalid_regex_raises_error() -> None:
    bad = parse_pack_dict(
        {
            "pack_id": "bad_v1",
            "source_type": "bad",
            "version": "1.0.0",
            "signatures": [{"name": "bad_sig", "pattern": "([invalid", "extracted_fields": EMPTY_FIELDS}],
        }
    )

    with pytest.raises(CompilationError):
        compile_pack(bad)
