"""
Reports Pydantic Schemas for NEXUS-Forecast Backend.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ReportMetadata(BaseModel):
    id: str
    phase: str
    title: str
    category: str
    filename: str
    size_bytes: int
    last_modified: str
    summary: str


class ReportDetailResponse(BaseModel):
    id: str
    title: str
    filename: str
    content: str
    size_bytes: int
    last_modified: str
