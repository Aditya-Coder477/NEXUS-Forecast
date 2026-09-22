"""
Knowledge Enrichment Pydantic Schemas for NEXUS-Forecast Backend.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class MitreTechniqueSchema(BaseModel):
    id: str
    name: str
    tactic: str
    stage: str
    review_status: str
    url: Optional[str] = None
    description: Optional[str] = None


class CapecPatternSchema(BaseModel):
    id: str
    name: str
    abstraction: str
    likelihood_of_attack: str
    typical_severity: str
    execution_flow: List[str] = []
    mitigations: List[str] = []


class MitreKnowledgeResponse(BaseModel):
    total_techniques: int
    review_required_count: int
    stages: List[str]
    techniques: List[MitreTechniqueSchema]


class CapecKnowledgeResponse(BaseModel):
    total_patterns: int
    patterns: List[CapecPatternSchema]
