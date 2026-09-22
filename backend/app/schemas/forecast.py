"""
Forecast Pydantic Schemas for NEXUS-Forecast Backend.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ForecastSummaryItem(BaseModel):
    id: str
    timestamp: str
    scenario: str
    dataset: str
    attack_probability: float
    decision: str
    predicted_stage: str
    stage_confidence: float
    threat_level: str
    operational_threshold: float = 0.45


class ForecastDetailResponse(BaseModel):
    id: str
    timestamp: str
    scenario: str
    dataset: str
    attack_probability: float
    raw_logit: Optional[float] = None
    decision: str
    predicted_stage: str
    stage_confidence: float
    operational_threshold: float = 0.45
    timeline: List[Dict[str, Any]]
    rollout_horizons: Dict[str, Any]
    evidence: List[Dict[str, Any]]
    stage_progression: List[Dict[str, Any]]
    top_features: List[Dict[str, Any]]
