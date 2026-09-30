"""pipeline-svc/coldpath — C4: Drain clustering, embeddings, semantic mapping, confidence gate (M6)."""

from pipeline_svc.coldpath.confidence_gate import ConfidenceGate
from pipeline_svc.coldpath.draft_pack import DraftPackGenerator, template_to_regex
from pipeline_svc.coldpath.drain import DrainParser, LogCluster
from pipeline_svc.coldpath.onboarding import AutoOnboarder, ConflictError
from pipeline_svc.coldpath.semantic_mapper import SemanticMapper, check_type_compatibility

__all__ = [
    "AutoOnboarder",
    "ConfidenceGate",
    "ConflictError",
    "DraftPackGenerator",
    "DrainParser",
    "LogCluster",
    "SemanticMapper",
    "check_type_compatibility",
    "template_to_regex",
]
