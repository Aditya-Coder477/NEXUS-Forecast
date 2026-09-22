"""
Configuration dataclass and settings for NEXUS-Forecast Phase 19 Offline Inference.
"""

import os
from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class InferenceConfig:
    """Configuration settings for the offline inference pipeline."""

    # Manifest and security
    manifest_path: str = os.path.join("models", "manifest.json")
    strict_manifest_check: bool = True

    # Model and artifacts
    model_path: str = os.path.join("models", "world_model", "gru", "best_model.pt")
    scaler_path: str = os.path.join("models", "world_model", "gru", "scaler.joblib")
    calibration_path: str = os.path.join("models", "world_model", "gru", "calibration_model.joblib")
    calibration_config_path: str = os.path.join("models", "world_model", "gru", "calibration_config.json")
    baseline_path: str = os.path.join("models", "explainability", "baseline_statistics.json")

    # Knowledge bases
    mitre_stage_mapping_path: str = os.path.join("data", "knowledge", "mitre_attack", "processed", "attack_stage_mapping.json")
    mitre_techniques_path: str = os.path.join("data", "knowledge", "mitre_attack", "processed", "techniques.json")
    capec_path: str = os.path.join("data", "knowledge", "capec", "processed", "capec_normalized.json")

    # Thresholds and operational parameters
    operational_threshold: float = 0.45
    horizons: List[int] = field(default_factory=lambda: [1, 3, 6])
    sequence_length: int = 10
    num_features: int = 22
    window_size_seconds: int = 60
    step_size_seconds: int = 30

    # Pipeline execution modes
    explain_mode: str = "lightweight"  # "none", "lightweight", "full"
    enrich_mode: str = "full"         # "none", "attack", "full"
    device: str = "cpu"
    batch_size: int = 64

    def validate(self) -> None:
        """Validate configuration settings."""
        if self.operational_threshold < 0.0 or self.operational_threshold > 1.0:
            raise ValueError(f"Operational threshold must be in [0, 1], got {self.operational_threshold}")
        if self.sequence_length != 10:
            raise ValueError(f"Sequence length must be exactly 10, got {self.sequence_length}")
        if self.num_features != 22:
            raise ValueError(f"Feature count must be exactly 22, got {self.num_features}")
        if self.explain_mode not in ["none", "lightweight", "full"]:
            raise ValueError(f"Invalid explain_mode: {self.explain_mode}. Must be one of 'none', 'lightweight', 'full'")
        if self.enrich_mode not in ["none", "attack", "full"]:
            raise ValueError(f"Invalid enrich_mode: {self.enrich_mode}. Must be one of 'none', 'attack', 'full'")
