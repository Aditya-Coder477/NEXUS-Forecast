"""
Inference Pydantic Schemas for NEXUS-Forecast Backend.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class InferenceRequest(BaseModel):
    input_type: str = Field(default="demo", description="'demo', 'scenario', 'state', or 'file'")
    dataset: Optional[str] = Field(default="CIC-IDS2017", description="Dataset baseline name")
    scenario_id: Optional[str] = Field(default="scenario_01", description="Scenario identifier if scenario selected")
    raw_sequence: Optional[List[List[float]]] = Field(default=None, description="Raw 10x22 state array if input_type='state'")
    horizons: List[int] = Field(default=[1, 3, 6], description="Forecast horizons in 30s steps")
    explain_mode: str = Field(default="lightweight", description="'none', 'lightweight', or 'full'")
    enrich_mode: str = Field(default="full", description="'none', 'attack', or 'full'")


class HorizonForecastDetail(BaseModel):
    horizon_step: int
    horizon_seconds: int
    raw_attack_logit: float
    calibrated_attack_prob: float
    predicted_attack: bool
    threshold: float
    predicted_stage: str
    stage_confidence: float
    stage_probabilities: Dict[str, float]
    forecasted_state_physical: Dict[str, float]
    explanation: Optional[Dict[str, Any]] = None
    enrichment: Optional[Dict[str, Any]] = None


class InferenceResponse(BaseModel):
    forecast_id: str
    timestamp: str
    device: str
    execution_time_ms: float
    origin_window_index: int
    horizons: Dict[str, HorizonForecastDetail]
    summary: Dict[str, Any]
    meta: Dict[str, Any]
