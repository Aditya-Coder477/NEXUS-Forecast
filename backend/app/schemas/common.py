"""
Common Pydantic Schemas for NEXUS-Forecast Backend.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str = "1.0.0"
    mode: str = "offline"
    air_gapped: bool = True
    manifest_valid: bool = True
    active_device: str = "cpu"


class PipelineStatusResponse(BaseModel):
    status: str
    version: str
    operational_threshold: float = 0.45
    sequence_length: int = 10
    num_features: int = 22
    horizons: List[int] = [1, 3, 6]
    artifacts: Dict[str, Dict[str, Any]]
