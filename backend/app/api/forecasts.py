"""
Forecasts and Overview API router.
"""

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Query
from backend.app.schemas.forecast import ForecastSummaryItem
from backend.app.services.forecast_service import ForecastService
from backend.app.services.knowledge_service import KnowledgeService

router = APIRouter(tags=["Forecasts"])


@router.get("/forecasts", response_model=List[ForecastSummaryItem])
def list_forecasts(
    dataset: Optional[str] = Query(default=None, description="Filter by dataset name"),
    scenario: Optional[str] = Query(default=None, description="Filter by scenario name or ID"),
    decision: Optional[str] = Query(default=None, description="Filter by decision (ATTACK or BENIGN)"),
    stage: Optional[str] = Query(default=None, description="Filter by predicted stage"),
    horizon: Optional[str] = Query(default=None, description="Filter by horizon (+30s, +90s, +180s)"),
    limit: int = Query(default=50, ge=1, le=100)
):
    """Retrieve historical forecasts and benchmark scenarios with optional filtering."""
    return ForecastService.list_forecasts(
        dataset=dataset,
        scenario=scenario,
        decision=decision,
        stage=stage,
        horizon=horizon,
        limit=limit
    )


@router.get("/forecasts/{forecast_id}")
def get_forecast_detail(forecast_id: str):
    """Retrieve comprehensive forecast detail by ID."""
    fc = ForecastService.get_forecast_by_id(forecast_id)
    if fc:
        # If wrapped live item, return raw detail or normalized item
        if isinstance(fc, dict) and "raw_detail" in fc:
            return fc["raw_detail"]
        return fc

    raise HTTPException(status_code=404, detail=f"Forecast '{forecast_id}' not found")


@router.get("/forecasts/{forecast_id}/knowledge")
def get_forecast_knowledge(forecast_id: str):
    """Retrieve enriched threat intelligence for a forecast."""
    sc = ForecastService.get_scenario_by_id(forecast_id)
    if not sc:
        raise HTTPException(status_code=404, detail=f"Forecast '{forecast_id}' not found")
    
    stage = sc.get("predicted_stage", "DISCOVERY")
    mitre_data = KnowledgeService.get_mitre_knowledge(stage_filter=stage)
    capec_data = KnowledgeService.get_capec_knowledge(query=stage, limit=10)
    
    return {
        "forecast_id": forecast_id,
        "predicted_stage": stage,
        "mitre_techniques": mitre_data.get("techniques", [])[:10],
        "capec_patterns": capec_data.get("patterns", [])[:10]
    }


@router.get("/dashboard/overview")
def get_dashboard_overview(
    dataset: str = "CIC-IDS2017",
    scenario: str = "Scenario 01",
    time_range: str = "Apr 21, 2024 10:00–11:00"
):
    """
    Overview endpoint serving all primary cards, timeline, evidence, and progression
    for the System Dashboard.
    """
    scenarios = ForecastService.get_all_scenarios()
    
    # Match scenario by prefix or name
    selected = None
    if scenarios:
        for s in scenarios:
            if scenario.lower() in s["id"].lower() or scenario.lower() in s["name"].lower():
                selected = ForecastService.get_scenario_by_id(s["id"])
                break
        if not selected:
            selected = ForecastService.get_scenario_by_id(scenarios[0]["id"])

    # Fallback default values
    if not selected:
        selected = {
            "scenario_id": "scenario_01",
            "scenario_name": "PortScan Friday",
            "probability": 0.82,
            "threshold": 0.45,
            "predicted_attack": True,
            "predicted_stage": "DISCOVERY",
            "stage_confidence": 0.764,
            "timeline": [],
            "evidence": [],
            "stage_progression": [],
            "top_features": []
        }

    prob = round(float(selected.get("calibrated_attack_probability", selected.get("probability", 0.82))), 4)
    stage = selected.get("predicted_stage", "DISCOVERY")
    if stage == "BENIGN" and prob >= 0.45:
        stage = "DISCOVERY"
    decision = "ATTACK" if prob >= 0.45 else "BENIGN"

    return {
        "dataset": dataset,
        "scenario": selected.get("scenario_name", scenario),
        "primary_forecast": {
            "attack_probability": prob,
            "threshold": 0.45,
            "predicted_stage": stage,
            "stage_confidence": round(float(selected.get("stage_confidence", 0.764)), 4),
            "decision": decision
        },
        "timeline": selected.get("timeline", [
            {"label": "t-150s", "probability": 0.12, "type": "observed"},
            {"label": "t-120s", "probability": 0.15, "type": "observed"},
            {"label": "t-90s", "probability": 0.28, "type": "observed"},
            {"label": "t-60s", "probability": 0.42, "type": "observed"},
            {"label": "t-30s", "probability": 0.65, "type": "observed"},
            {"label": "Now (t)", "probability": 0.78, "type": "current"},
            {"label": "t+30s", "probability": 0.82, "type": "forecast"},
            {"label": "t+90s", "probability": 0.88, "type": "forecast"},
            {"label": "t+180s", "probability": 0.93, "type": "forecast"},
        ]),
        "evidence": selected.get("evidence", [
            {"id": "ev-1", "feature": "flow_count", "label": "Flow Rate Surge", "val": "4,820 flows/min", "norm": "82 flows/min", "dev": "+5,778%", "stage": "DISCOVERY", "desc": "Extreme packet exchange rate detected across sequential external destination ports."},
            {"id": "ev-2", "feature": "syn_flag_ratio", "label": "SYN Flag Asymmetry", "val": "0.94", "norm": "0.08", "dev": "+1,075%", "stage": "DISCOVERY", "desc": "High ratio of SYN packets with no corresponding ACK, characteristic of stealth SYN port scanning."},
            {"id": "ev-3", "feature": "unique_dst_ports", "label": "Port Dispersion Anomaly", "val": "1,240 ports", "norm": "4.2 ports", "dev": "+2,852%", "stage": "DISCOVERY", "desc": "Traffic directed toward wide span of TCP service endpoints within single 60s temporal observation window."},
            {"id": "ev-4", "feature": "mean_flow_duration", "label": "Truncated Flow Duration", "val": "0.04 ms", "norm": "12.8 ms", "dev": "-99.7%", "stage": "DISCOVERY", "desc": "Flows terminated immediately upon probe response receipt without data payload exchange."}
        ]),
        "stage_progression": selected.get("stage_progression", [
            {"stage": "RECONNAISSANCE", "status": "completed", "prob": 0.95},
            {"stage": "INITIAL_ACCESS", "status": "completed", "prob": 0.88},
            {"stage": "EXECUTION", "status": "active", "prob": 0.82},
            {"stage": "PERSISTENCE", "status": "imminent", "prob": 0.68},
            {"stage": "PRIVILEGE_ESCALATION", "status": "predicted", "prob": 0.44},
            {"stage": "DEFENSE_EVASION", "status": "predicted", "prob": 0.31},
            {"stage": "CREDENTIAL_ACCESS", "status": "latent", "prob": 0.18},
            {"stage": "EXFILTRATION", "status": "latent", "prob": 0.08},
        ]),
        "top_features": selected.get("top_features", [
            {"feature": "syn_flag_ratio", "attribution": 0.312, "relative_weight": 0.312, "desc": "SYN packet asymmetry"},
            {"feature": "unique_dst_ports", "attribution": 0.254, "relative_weight": 0.254, "desc": "Destination port dispersion"},
            {"feature": "flow_count", "attribution": 0.188, "relative_weight": 0.188, "desc": "Aggregate flow rate"},
            {"feature": "fwd_pkts_per_sec", "attribution": 0.126, "relative_weight": 0.126, "desc": "Forward packet frequency"},
            {"feature": "mean_flow_duration", "attribution": 0.071, "relative_weight": 0.071, "desc": "Flow duration contraction"}
        ]),
        "recent_forecasts": ForecastService.list_forecasts(limit=5)
    }
