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


_dataset_sequence_cache: Dict[str, np.ndarray] = {}


def get_sequences_for_dataset(dataset_name: Optional[str]) -> np.ndarray:
    """Retrieve and cache canonical test-partition sequence arrays [N, 10, 22] for a specific dataset."""
    global _dataset_sequence_cache
    ds = (dataset_name or "CIC-IDS2017").upper()

    if "UNSW" in ds:
        key = "UNSW-NB15"
        filename = "unsw_nb15_sequences.parquet"
    elif "CTU" in ds:
        key = "CTU-13"
        filename = "ctu13_sequences.parquet"
    else:
        key = "CIC-IDS2017"
        filename = "cic_ids2017_sequences.parquet"

    if key in _dataset_sequence_cache:
        return _dataset_sequence_cache[key]

    target_path = settings.BASE_DIR / "data" / "processed" / "forecast_sequences" / filename
    if not target_path.exists():
        target_path = settings.BASE_DIR / "data" / "demo" / "example_sequence.parquet"

    if target_path.exists():
        df = pd.read_parquet(target_path)
        if "split" in df.columns:
            test_df = df[df["split"] == "TEST"]
            if len(test_df) > 0:
                df = test_df
        # Cache first 50 test sequences for responsive offline performance
        sub_df = df.head(50)
        seqs = InputValidator.extract_sequences_from_dataframe(sub_df)
        _dataset_sequence_cache[key] = seqs
        return seqs

    raise FileNotFoundError(f"Sequence repository not found for dataset '{key}' at {target_path}")


class InferenceService:
    @staticmethod
    def run_inference(
        input_type: str = "demo",
        dataset: Optional[str] = "CIC-IDS2017",
        scenario_id: Optional[str] = None,
        raw_sequence: Optional[List[List[float]]] = None,
        horizons: List[int] = [1, 3, 6],
        explain_mode: str = "lightweight",
        enrich_mode: str = "full",
    ) -> Dict[str, Any]:
        """
        Execute an offline inference pass on the requested input and dataset baseline.
        """
        pipeline = get_inference_pipeline()

        # Determine sequence array [10, 22]
        if input_type == "state" and raw_sequence is not None:
            arr = np.array(raw_sequence, dtype=np.float64)
            if arr.shape != (10, 22):
                raise ValueError(f"State input must have shape (10, 22), got {arr.shape}")
        elif input_type in ["demo", "scenario", "sequence", "parquet", "flows"]:
            seqs = get_sequences_for_dataset(dataset)

            # Select specific index based on scenario if available
            idx = 0
            if scenario_id:
                clean_id = scenario_id.lower().replace("scenario_", "").replace("scenario ", "").strip()
                # Extract first integer if present
                import re
                m = re.search(r"\d+", clean_id)
                if m:
                    idx = (int(m.group()) - 1) % seqs.shape[0]
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
