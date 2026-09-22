"""
Explanations API router.
"""

from fastapi import APIRouter, HTTPException
from backend.app.schemas.explanation import ExplanationResponse
from backend.app.services.explanation_service import ExplanationService

router = APIRouter(tags=["Explanations"])


@router.get("/explanations", response_model=ExplanationResponse)
@router.get("/explanations/{forecast_id}", response_model=ExplanationResponse)
def get_explanation(forecast_id: str = "scenario_01"):
    """Retrieve full attribution, temporal curves, 10x22 matrix, and evidence for a forecast."""
    res = ExplanationService.get_explanation(forecast_id)
    if not res:
        raise HTTPException(status_code=404, detail=f"Explanation for '{forecast_id}' not found")
    return res
