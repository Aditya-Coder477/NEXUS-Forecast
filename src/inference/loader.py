"""
Cryptographic Model and Artifact Loader for Phase 19.
Verifies all file hashes against models/manifest.json before loading any code or model weights.
"""

import os
import json
import hashlib
import logging
import joblib
import torch
from typing import Dict, Any, Tuple

from src.inference.config import InferenceConfig
from src.world_model.gru_model import GRUWorldModel
from src.knowledge_enrichment.mitre_enricher import MitreEnricher
from src.knowledge_enrichment.capec_enricher import CapecEnricher
from src.knowledge_enrichment.forecast_enricher import ForecastEnricher

logger = logging.getLogger(__name__)


class IntegrityError(RuntimeError):
    """Raised when an artifact checksum does not match the authoritative manifest."""
    pass


class ModelLoader:
    """
    Loads and validates all pipeline artifacts with strict cryptographic checksum checking.
    """

    def __init__(self, config: InferenceConfig):
        self.config = config
        self.config.validate()

    @staticmethod
    def calculate_sha256(filepath: str) -> str:
        """Compute SHA256 hex digest of a local file."""
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def verify_manifest(self) -> Dict[str, bool]:
        """
        Verify every artifact in models/manifest.json matches its expected SHA256 digest.
        Raises IntegrityError if any checksum mismatches.
        """
        if not os.path.exists(self.config.manifest_path):
            raise FileNotFoundError(f"Manifest not found at {self.config.manifest_path}")

        with open(self.config.manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        artifacts = manifest.get("artifacts", {})
        results = {}
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

        for rel_path, meta in artifacts.items():
            expected_hash = meta["sha256"]

            # Anchor path resolution to project root first, then cwd
            resolved_path = None
            for base in [project_root, os.getcwd()]:
                candidate = os.path.normpath(os.path.join(base, rel_path))
                if os.path.exists(candidate):
                    resolved_path = candidate
                    break

            if not resolved_path:
                raise IntegrityError(f"Mandatory pipeline artifact missing: {rel_path}")

            actual_hash = self.calculate_sha256(resolved_path)
            if actual_hash != expected_hash:
                # Handle cross-platform line-ending differences (CRLF vs LF) for text/JSON artifacts
                if resolved_path.endswith((".json", ".txt", ".csv", ".md")):
                    with open(resolved_path, "rb") as f:
                        raw_bytes = f.read()
                    crlf_hash = hashlib.sha256(raw_bytes.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")).hexdigest()
                    lf_hash = hashlib.sha256(raw_bytes.replace(b"\r\n", b"\n")).hexdigest()
                    if expected_hash in (crlf_hash, lf_hash):
                        actual_hash = expected_hash

            if actual_hash != expected_hash:
                raise IntegrityError(
                    f"Cryptographic hash mismatch for {rel_path}!\n"
                    f"Expected: {expected_hash}\n"
                    f"Actual:   {actual_hash}"
                )
            results[rel_path] = True

        logger.info(f"Cryptographic integrity verified for all {len(results)} artifacts in manifest.")
        return results

    def load_pipeline_components(self) -> Dict[str, Any]:
        """
        Verify manifest and load all models, scalers, and knowledge bases into memory.
        """
        if self.config.strict_manifest_check:
            self.verify_manifest()

        device = torch.device(self.config.device)

        # 1. Load GRU Model
        logger.info(f"Loading GRU World Model from: {self.config.model_path}")
        model = GRUWorldModel(
            input_size=self.config.num_features,
            hidden_size=128,
            num_layers=2,
            forecast_horizons=self.config.horizons,
        )
        checkpoint = torch.load(self.config.model_path, map_location=device, weights_only=False)
        if "model_state_dict" in checkpoint:
            model.load_state_dict(checkpoint["model_state_dict"])
        elif isinstance(checkpoint, dict) and "gru.weight_ih_l0" in checkpoint:
            model.load_state_dict(checkpoint)
        elif hasattr(checkpoint, "state_dict"):
            model.load_state_dict(checkpoint.state_dict())
        else:
            model.load_state_dict(checkpoint)

        model.to(device)
        model.eval()

        # 2. Load Scaler
        logger.info(f"Loading StandardScaler from: {self.config.scaler_path}")
        scaler = joblib.load(self.config.scaler_path)

        # 3. Load Platt Calibration Model & Config
        logger.info(f"Loading Calibration model from: {self.config.calibration_path}")
        calibration_model = joblib.load(self.config.calibration_path)

        with open(self.config.calibration_config_path, "r", encoding="utf-8") as f:
            calibration_config = json.load(f)

        # 4. Load Baseline Statistics for Explainability
        baseline_stats = None
        if os.path.exists(self.config.baseline_path):
            with open(self.config.baseline_path, "r", encoding="utf-8") as f:
                baseline_stats = json.load(f)

        # 5. Load Knowledge Enrichers
        mitre_enricher = MitreEnricher(
            stage_mapping_path=self.config.mitre_stage_mapping_path,
            techniques_path=self.config.mitre_techniques_path,
        )
        capec_enricher = CapecEnricher(capec_path=self.config.capec_path)
        forecast_enricher = ForecastEnricher(
            mitre_enricher=mitre_enricher,
            capec_enricher=capec_enricher,
        )

        return {
            "model": model,
            "scaler": scaler,
            "calibration_model": calibration_model,
            "calibration_config": calibration_config,
            "baseline_stats": baseline_stats,
            "mitre_enricher": mitre_enricher,
            "capec_enricher": capec_enricher,
            "forecast_enricher": forecast_enricher,
            "device": device,
        }
