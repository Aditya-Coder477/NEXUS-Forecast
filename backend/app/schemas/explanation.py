"""
Explanation Pydantic Schemas for NEXUS-Forecast Backend.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class FeatureAttributionItem(BaseModel):
    feature_name: str
    attribution_score: float
    percentage: float
    baseline_mean: float
    observed_value: float
    category: str


class TemporalAttributionItem(BaseModel):
    window_index: int
    offset_seconds: int
    attribution_score: float
    relative_weight: float
    window: Optional[str] = None
    relative_seconds: Optional[str] = None
    attribution: Optional[float] = None
    state_summary: Optional[str] = None


class ExplanationResponse(BaseModel):
    forecast_id: str
    method: str = "Integrated Gradients (50 steps)"
    completeness_delta: float
    top_features: List[FeatureAttributionItem]
    temporal_attribution: List[TemporalAttributionItem]
    feature_time_matrix: Dict[str, Any]
    flow_evidence: List[Dict[str, Any]]
    counterfactual_sensitivity: List[Dict[str, Any]]
    feature_attribution: Optional[List[Dict[str, Any]]] = None
    heatmap_matrix: Optional[List[Dict[str, Any]]] = None
    sensitivity: Optional[List[Dict[str, Any]]] = None
    error_analysis: Optional[Dict[str, Any]] = None
