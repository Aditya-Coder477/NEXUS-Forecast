"""
Forecast Service for querying scenarios and historical forecast records.
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from backend.app.config import settings

_cached_scenarios: Optional[List[Dict[str, Any]]] = None
_forecast_history: List[Dict[str, Any]] = []


def load_scenarios() -> List[Dict[str, Any]]:
    """Load pre-computed scenarios from Phase 17 representative explanations."""
    global _cached_scenarios
    if _cached_scenarios is None:
        p17_file = settings.reports_dir / "phase17" / "representative_explanations.json"
        if p17_file.exists():
            with open(p17_file, "r", encoding="utf-8") as f:
                _cached_scenarios = json.load(f)
        else:
            _cached_scenarios = []
    return _cached_scenarios


class ForecastService:
    @staticmethod
    def get_all_scenarios() -> List[Dict[str, Any]]:
        """Return list of available evaluation scenarios."""
        scenarios = load_scenarios()
        summaries = []
        for idx, s in enumerate(scenarios):
            sid = f"scenario_{idx+1:02d}"
            orig_sid = s.get("scenario_id", "Friday-DDoS")
            prob = s.get("calibrated_attack_probability", s.get("probability", 0.0))
            gt_attack = s.get("ground_truth", {}).get("attack_occurred", True) if isinstance(s.get("ground_truth"), dict) else True
            pred_attack = s.get("forecast_decision", {}).get("alert", True) if isinstance(s.get("forecast_decision"), dict) else (prob >= settings.operational_threshold)
            pred_stage = s.get("predicted_stage", "DISCOVERY")
            if pred_stage == "BENIGN" and prob >= settings.operational_threshold:
                pred_stage = "DISCOVERY"

            label_name = f"Scenario {idx+1:02d} ({orig_sid.split('-')[-1]} window {idx+1})"
            summaries.append({
                "id": sid,
                "name": label_name,
                "dataset": s.get("dataset", "CIC-IDS2017"),
                "category": s.get("outcome_group", "TP"),
                "attack_type": orig_sid.split("-")[-1] if "-" in orig_sid else "Attack",
                "attack_probability": round(float(prob), 4),
                "ground_truth_attack": gt_attack,
                "predicted_attack": pred_attack,
                "predicted_stage": pred_stage,
                "time_range": s.get("prediction_origin", "2017-07-07 04:46:30")
            })
        return summaries

    @staticmethod
    def get_scenario_by_id(scenario_id: str) -> Optional[Dict[str, Any]]:
        """Return full scenario object by ID."""
        scenarios = load_scenarios()
        clean = scenario_id.lower().replace("scenario_", "").replace("scenario ", "").strip()
        if clean.isdigit():
            idx = int(clean) - 1
            if 0 <= idx < len(scenarios):
                return scenarios[idx]
        for idx, s in enumerate(scenarios):
            if f"scenario_{idx+1:02d}" == scenario_id or s.get("scenario_id") == scenario_id or s.get("scenario_name") == scenario_id:
                return s
        return scenarios[0] if scenarios else None

    @staticmethod
    def list_forecasts(
        dataset: Optional[str] = None,
        scenario: Optional[str] = None,
        decision: Optional[str] = None,
        stage: Optional[str] = None,
        horizon: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """List historical forecasts combined with cached scenarios with query filtering."""
        scenarios = load_scenarios()
        all_items = []

        # 1. Add dynamic live forecasts first (newest first)
        for f in reversed(_forecast_history):
            all_items.append(f)

        # 2. Add representative pre-computed scenarios
        for s in scenarios:
            sid = s.get("scenario_id", "")
            prob = s.get("calibrated_attack_probability", s.get("probability", 0.0))
            stg = s.get("predicted_stage", "DISCOVERY")
            if stg == "BENIGN" and prob >= settings.operational_threshold:
                stg = "DISCOVERY"

            origin_ts = s.get("prediction_origin", "2017-07-07 04:46:30")
            h_sec = s.get("forecast_horizon_seconds", 30)

            all_items.append({
                "id": sid,
                "timestamp": origin_ts,
                "scenario": sid.replace("-", " ").replace("WorkingHours", "Session"),
                "dataset": s.get("dataset", "CIC-IDS2017"),
                "horizon": f"+{h_sec}s",
                "attack_probability": round(float(prob), 4),
                "decision": "ATTACK" if prob >= settings.operational_threshold else "BENIGN",
                "predicted_stage": stg,
                "stage_confidence": round(float(s.get("stage_confidence", 0.75)), 4),
                "threat_level": "CRITICAL" if prob >= 0.85 else ("HIGH" if prob >= 0.65 else ("ELEVATED" if prob >= 0.45 else "BENIGN")),
                "operational_threshold": settings.operational_threshold
            })

        # Apply filtering
        filtered = []
        for item in all_items:
            if decision and decision.upper() != "ALL" and item.get("decision", "").upper() != decision.upper():
                continue
            if stage and stage.upper() != "ALL" and item.get("predicted_stage", "").upper() != stage.upper():
                continue
            if horizon and horizon.upper() != "ALL":
                item_h = item.get("horizon", "+30s")
                if horizon not in item_h and item_h not in horizon:
                    continue
            if dataset and dataset.upper() != "ALL" and dataset.lower() not in item.get("dataset", "").lower():
                continue
            if scenario and scenario.upper() != "ALL" and scenario.lower() not in item.get("scenario", "").lower() and scenario.lower() not in item.get("id", "").lower():
                continue
            filtered.append(item)

        return filtered[:limit]

    @staticmethod
    def get_forecast_by_id(forecast_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve forecast detail by ID from live history or cached scenarios."""
        # 1. Check live history
        for f in _forecast_history:
            if f.get("id") == forecast_id:
                return f
        # 2. Check cached scenarios
        return ForecastService.get_scenario_by_id(forecast_id)

    @staticmethod
    def record_forecast(forecast_data: Dict[str, Any], scenario_name: str = "Live Inference", dataset_name: str = "CIC-IDS2017") -> None:
        """Store newly generated forecast in in-memory history."""
        fid = forecast_data.get("forecast_id", "")
        summary = forecast_data.get("summary", {})
        h1 = forecast_data.get("horizons", {}).get("h1", {})
        prob = h1.get("calibrated_attack_prob", summary.get("max_attack_prob", 0.0))
        item = {
            "id": fid,
            "timestamp": forecast_data.get("timestamp", "2026-09-22 03:00:00 UTC"),
            "scenario": scenario_name,
            "dataset": dataset_name,
            "horizon": "+30s",
            "attack_probability": round(float(prob), 4),
            "decision": "ATTACK" if prob >= settings.operational_threshold else "BENIGN",
            "predicted_stage": h1.get("predicted_stage", "BENIGN"),
            "stage_confidence": round(float(h1.get("stage_confidence", 0.0)), 4),
            "threat_level": summary.get("threat_level", "BENIGN"),
            "operational_threshold": settings.operational_threshold,
            "raw_detail": forecast_data
        }
        _forecast_history.append(item)
