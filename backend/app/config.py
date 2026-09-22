"""
NEXUS-Forecast Phase 21 Backend Configuration.
Air-gapped local environment settings with zero external network access.
"""

import os
from pathlib import Path
from pydantic import BaseModel

# Project Root Directory
BASE_DIR = Path(__file__).resolve().parent.parent.parent
STATIC_DIR = BASE_DIR / "src" / "dashboard" / "static"
MODELS_DIR = BASE_DIR / "models"
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"

class BackendSettings(BaseModel):
    app_name: str = "NEXUS-Forecast Analyst Workstation"
    version: str = "1.0.0"
    offline_mode: bool = True
    device: str = "cpu"
    operational_threshold: float = 0.45
    
    # Base Dirs
    BASE_DIR: Path = BASE_DIR
    STATIC_DIR: Path = STATIC_DIR
    MODELS_DIR: Path = MODELS_DIR
    DATA_DIR: Path = DATA_DIR
    REPORTS_DIR: Path = REPORTS_DIR
    
    # Model Artifacts
    model_path: Path = MODELS_DIR / "world_model" / "gru" / "best_model.pt"
    scaler_path: Path = MODELS_DIR / "world_model" / "gru" / "scaler.joblib"
    calibration_path: Path = MODELS_DIR / "world_model" / "gru" / "calibration_model.joblib"
    baseline_path: Path = MODELS_DIR / "explainability" / "baseline_statistics.json"
    manifest_path: Path = MODELS_DIR / "manifest.json"
    
    # Knowledge Artifacts
    mitre_stage_mapping_path: Path = DATA_DIR / "knowledge" / "mitre_attack" / "processed" / "attack_stage_mapping.json"
    mitre_techniques_path: Path = DATA_DIR / "knowledge" / "mitre_attack" / "processed" / "techniques.json"
    capec_path: Path = DATA_DIR / "knowledge" / "capec" / "processed" / "capec_normalized.json"
    
    # Static UI
    static_dir: Path = STATIC_DIR
    reports_dir: Path = REPORTS_DIR

settings = BackendSettings()
