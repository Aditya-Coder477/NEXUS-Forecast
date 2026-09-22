"""
Inference Service wrapping the frozen OfflineInferencePipeline singleton.
"""

import os
import uuid
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional

from src.inference.config import InferenceConfig
from src.inference.pipeline import OfflineInferencePipeline
from src.inference.validator import InputValidator, ValidationError
from backend.app.config import settings

_pipeline_instance: Optional[OfflineInferencePipeline] = None


def get_inference_pipeline() -> OfflineInferencePipeline:
    """Retrieve or initialize the singleton OfflineInferencePipeline."""
    global _pipeline_instance
    if _pipeline_instance is None:
        cfg = InferenceConfig(
            device=settings.device,
            operational_threshold=settings.operational_threshold,
            model_path=str(settings.model_path),
            scaler_path=str(settings.scaler_path),
            calibration_path=str(settings.calibration_path),
            baseline_path=str(settings.baseline_path),
            manifest_path=str(settings.manifest_path),
            mitre_stage_mapping_path=str(settings.mitre_stage_mapping_path),
            mitre_techniques_path=str(settings.mitre_techniques_path),
            capec_path=str(settings.capec_path),
        )
        _pipeline_instance = OfflineInferencePipeline(cfg)
    return _pipeline_instance


class InferenceService:
    @staticmethod
    def run_inference(
        input_type: str = "demo",
        scenario_id: Optional[str] = None,
        raw_sequence: Optional[List[List[float]]] = None,
        horizons: List[int] = [1, 3, 6],
        explain_mode: str = "lightweight",
        enrich_mode: str = "full",
    ) -> Dict[str, Any]:
        """
        Execute an offline inference pass on the requested input.
        """
        pipeline = get_inference_pipeline()

        # Determine sequence array [10, 22]
        if input_type == "state" and raw_sequence is not None:
            arr = np.array(raw_sequence, dtype=np.float64)
            if arr.shape != (10, 22):
                raise ValueError(f"State input must have shape (10, 22), got {arr.shape}")
        elif input_type in ["demo", "scenario", "sequence", "parquet", "flows"]:
            # Load sequence from demo parquet or scenario
            demo_path = settings.BASE_DIR / "data" / "demo" / "example_sequence.parquet"
            if not demo_path.exists():
                raise FileNotFoundError(f"Demo file not found at {demo_path}")
            df = pd.read_parquet(demo_path)
            seqs = InputValidator.extract_sequences_from_dataframe(df)
            
            # Select specific index based on scenario if available
            idx = 0
            if scenario_id:
                clean_id = scenario_id.lower().replace("scenario_", "").replace("scenario ", "").strip()
                if clean_id.isdigit():
                    idx = (int(clean_id) - 1) % seqs.shape[0]
            arr = seqs[idx]
        else:
            raise ValueError(f"Unsupported input_type: {input_type}")

        # Execute prediction
        result = pipeline.predict_single_sequence(
            x_raw=arr,
            explain_mode=explain_mode,
            enrich_mode=enrich_mode,
            forecast_id=f"NEXUS-FC-{uuid.uuid4().hex[:8].upper()}",
            origin_window_index=0
        )
        return result
