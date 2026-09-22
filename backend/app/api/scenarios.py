"""
Scenarios API router.
"""

from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException
from backend.app.services.forecast_service import ForecastService

router = APIRouter(tags=["Scenarios"])


@router.get("/scenarios", response_model=List[Dict[str, Any]])
def list_scenarios():
    """Retrieve pre-packaged validation scenarios (TP, TN, FP, FN)."""
    return ForecastService.get_all_scenarios()


@router.get("/scenarios/{scenario_id}")
def get_scenario(scenario_id: str):
    """Retrieve specific scenario details."""
    sc = ForecastService.get_scenario_by_id(scenario_id)
    if not sc:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found")
    return sc
