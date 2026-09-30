from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from ulpf_contracts import ExtractionEnvelope
from ulpf_contracts.generated.extraction_envelope_schema import PathTaken

if TYPE_CHECKING:
    from .coldpath.confidence_gate import ConfidenceGate
    from .coldpath.drain import DrainParser
    from .coldpath.semantic_mapper import SemanticMapper
    from .pack_registry import PackRegistry


class Router:
    def __init__(
        self,
        registry: PackRegistry,
        drain_parser: DrainParser | None = None,
        semantic_mapper: SemanticMapper | None = None,
        confidence_gate: ConfidenceGate | None = None,
    ) -> None:
        self.registry = registry
        self.drain_parser = drain_parser
        self.semantic_mapper = semantic_mapper
        self.confidence_gate = confidence_gate

    def route_and_extract(
        self,
        raw_payload: str | bytes,
        lineage_id: str | UUID,
        enable_cold_path: bool = True,
        sample_raw_pointer: str | None = None,
    ) -> ExtractionEnvelope | None:
        text = raw_payload.decode("utf-8", errors="replace") if isinstance(raw_payload, bytes) else raw_payload

        snapshot = self.registry.snapshot

        # 1. Hot Path: Deterministic Regex Evaluation
        for sig in snapshot.signatures:
            m = sig.regex.search(text)
            if m:
                extracted: dict[str, str] = {}
                for k, v in m.groupdict().items():
                    if v is not None:
                        extracted[k] = str(v)

                for field_name, source_expr in sig.extracted_fields.items():
                    if source_expr in extracted:
                        extracted[field_name] = extracted[source_expr]
                    elif source_expr.startswith("$"):
                        group_name = source_expr[1:]
                        if group_name in m.groupdict():
                            val = m.groupdict()[group_name]
                            if val is not None:
                                extracted[field_name] = str(val)
                    else:
                        extracted[field_name] = str(source_expr)

                confidence_scores = {k: 1.0 for k in extracted}
                uid = lineage_id if isinstance(lineage_id, UUID) else UUID(str(lineage_id))

                return ExtractionEnvelope(
                    lineage_id=uid,
                    path_taken=PathTaken.hot,
                    source_type=sig.source_type,
                    parser_version=sig.parser_version,
                    extracted_fields=extracted,
                    confidence_scores=confidence_scores,
                )

        # 2. Cold Path: Drain Clustering + Semantic Mapping + Confidence Gate
        if enable_cold_path and self.drain_parser and self.semantic_mapper and self.confidence_gate:
            cluster, _ = self.drain_parser.parse(text)
            variables = self.drain_parser.extract_variables(cluster, text)
            mapped = self.semantic_mapper.map_extracted_fields(variables)
            envelope, _ = self.confidence_gate.evaluate_and_route(
                lineage_id=lineage_id,
                source_type="cold_path_unmapped",
                cluster_id=cluster.cluster_id,
                mapped_fields=mapped,
                sample_raw_pointer=sample_raw_pointer,
            )
            return envelope

        return None

