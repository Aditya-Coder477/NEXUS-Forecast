"""
Schema definitions for Phase 18 ATT&CK and CAPEC Forecast Enrichment.
All models are strictly typed and serializable to dict/JSON.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Any, Optional


class KnowledgeRelevance(str, Enum):
    """
    Deterministic relevance levels of ATT&CK/CAPEC entities relative to forecast.
    """
    NOT_RELEVANT = "NOT_RELEVANT"
    CONTEXTUALLY_RELEVANT = "CONTEXTUALLY_RELEVANT"
    EVIDENCE_SUPPORTED = "EVIDENCE_SUPPORTED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class MappingConfidence(str, Enum):
    """
    Inherent confidence level of the knowledge mapping from MITRE to NEXUS stage.
    """
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class EvidenceCategory(str, Enum):
    """
    Authoritative evidence categories matching Phase 17 taxonomy.
    """
    TRAFFIC_VOLUME = "TRAFFIC_VOLUME"
    HOST_DIVERSITY = "HOST_DIVERSITY"
    PORT_DIVERSITY = "PORT_DIVERSITY"
    PROTOCOL_BEHAVIOR = "PROTOCOL_BEHAVIOR"
    CONNECTION_BEHAVIOR = "CONNECTION_BEHAVIOR"
    DIRECTIONALITY = "DIRECTIONALITY"
    TEMPORAL_PERSISTENCE = "TEMPORAL_PERSISTENCE"


@dataclass
class AttackTechnique:
    """
    Represents an enriched MITRE ATT&CK technique or subtechnique.
    """
    attack_id: str
    technique: str
    nexus_stage: str
    mitre_tactic: str
    all_mitre_tactics: List[str] = field(default_factory=list)
    mapping_confidence: str = MappingConfidence.HIGH.value
    mapping_reason: str = ""
    source: str = ""
    description: str = ""
    platforms: List[str] = field(default_factory=list)
    relevance: str = KnowledgeRelevance.CONTEXTUALLY_RELEVANT.value
    supporting_evidence_categories: List[str] = field(default_factory=list)
    evidence_notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CapecPattern:
    """
    Represents an enriched MITRE CAPEC attack pattern.
    """
    capec_id: str
    numeric_id: int
    name: str
    abstraction_level: str = "Standard"
    status: str = "Stable"
    description: str = ""
    typical_severity: str = "Medium"
    likelihood_of_attack: str = "Medium"
    prerequisites: List[str] = field(default_factory=list)
    consequences: List[Dict[str, Any]] = field(default_factory=list)
    related_attack_ids: List[str] = field(default_factory=list)
    relevance: str = KnowledgeRelevance.CONTEXTUALLY_RELEVANT.value
    supporting_evidence_categories: List[str] = field(default_factory=list)
    evidence_notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EnrichedHorizonForecast:
    """
    Enriched forecast output for a specific forecast horizon.
    """
    horizon_step: int
    horizon_seconds: int
    predicted_attack: bool
    calibrated_attack_prob: float
    predicted_stage: str
    stage_confidence: float
    top_evidence_categories: List[str] = field(default_factory=list)
    attack_techniques: List[AttackTechnique] = field(default_factory=list)
    capec_patterns: List[CapecPattern] = field(default_factory=list)
    unresolved_review_items: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "horizon_step": self.horizon_step,
            "horizon_seconds": self.horizon_seconds,
            "predicted_attack": self.predicted_attack,
            "calibrated_attack_prob": round(float(self.calibrated_attack_prob), 4),
            "predicted_stage": self.predicted_stage,
            "stage_confidence": round(float(self.stage_confidence), 4),
            "top_evidence_categories": self.top_evidence_categories,
            "attack_techniques": [t.to_dict() for t in self.attack_techniques],
            "capec_patterns": [c.to_dict() for c in self.capec_patterns],
            "unresolved_review_items": self.unresolved_review_items,
        }


@dataclass
class EnrichedForecastResult:
    """
    Comprehensive multi-horizon forecast enriched with MITRE ATT&CK and CAPEC.
    """
    forecast_id: str
    timestamp: str
    origin_window_index: int
    horizons: Dict[str, EnrichedHorizonForecast] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "forecast_id": self.forecast_id,
            "timestamp": self.timestamp,
            "origin_window_index": self.origin_window_index,
            "horizons": {k: v.to_dict() for k, v in self.horizons.items()},
            "summary": self.summary,
            "meta": self.meta,
        }
