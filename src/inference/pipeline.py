"""
Full Offline Inference Pipeline for NEXUS-Forecast Phase 19.
Integrates input validation, scaling, GRU multi-step rollout, Platt calibration,
Phase 17 explainability, and Phase 18 MITRE ATT&CK / CAPEC enrichment into a
unified, air-gapped execution flow.
"""

import os
import time
import uuid
import datetime
import logging
import numpy as np
import pandas as pd
import torch
from typing import Dict, List, Any, Optional, Union

from src.inference.config import InferenceConfig
from src.inference.loader import ModelLoader
from src.inference.validator import InputValidator, ValidationError
from src.world_model.dataset import STATE_FEATURE_NAMES, STAGE_VOCABULARY, IDX_TO_STAGE
from src.explainability.baseline import BaselineManager
from src.explainability.integrated_gradients import IntegratedGradientsExplainer
from src.knowledge_enrichment.schemas import KnowledgeRelevance

logger = logging.getLogger(__name__)


class OfflineInferencePipeline:
    """
    Unified, air-gapped inference engine for temporal network attack forecasting.
    """

    def __init__(self, config: Optional[InferenceConfig] = None):
        self.config = config or InferenceConfig()
        self.config.validate()

        # Load all components cryptographically
        self.loader = ModelLoader(self.config)
        components = self.loader.load_pipeline_components()

        self.model = components["model"]
        self.scaler = components["scaler"]
        self.calibration_model = components["calibration_model"]
        self.calibration_config = components["calibration_config"]
        self.baseline_stats = components["baseline_stats"]
        self.mitre_enricher = components["mitre_enricher"]
        self.capec_enricher = components["capec_enricher"]
        self.forecast_enricher = components["forecast_enricher"]
        self.device = components["device"]

        # Initialize BaselineManager for explainability if available
        self.baseline_manager = None
        if os.path.exists(self.config.baseline_path):
            try:
                bm = BaselineManager(scaler=self.scaler)
                bm.load(self.config.baseline_path)
                self.baseline_manager = bm
            except Exception as e:
                logger.warning(f"Could not initialize BaselineManager: {e}")

        # Initialize IntegratedGradientsExplainer
        self.ig_explainer = IntegratedGradientsExplainer(self.model, self.device)

        logger.info("OfflineInferencePipeline initialized and ready for inference.")

    def calibrate_logit(self, logit: float, horizon: int = 1) -> float:
        """Apply Platt scaling to a raw attack logit for the given horizon."""
        arr = np.array([logit], dtype=np.float64)
        if isinstance(self.calibration_model, dict):
            calibrator = self.calibration_model.get(horizon, self.calibration_model.get(1))
            if hasattr(calibrator, "calibrate"):
                return float(calibrator.calibrate(arr)[0])
            elif hasattr(calibrator, "predict_proba"):
                return float(calibrator.predict_proba(arr.reshape(-1, 1))[0, 1])
        elif hasattr(self.calibration_model, "calibrate"):
            return float(self.calibration_model.calibrate(arr)[0])
        elif hasattr(self.calibration_model, "predict_proba"):
            return float(self.calibration_model.predict_proba(arr.reshape(-1, 1))[0, 1])
        return float(1.0 / (1.0 + np.exp(-logit)))

    def _compute_lightweight_saliency_all(
        self, x_scaled_tensor: torch.Tensor, horizons: List[int]
    ) -> Dict[int, List[str]]:
        """Fast input gradient x input saliency for all horizons with single forward pass."""
        x_clone = x_scaled_tensor.clone().detach().requires_grad_(True)
        out = self.model(x_clone)
        results = {}
        for idx, h in enumerate(horizons):
            target = out["attack"][h]
            is_last = (idx == len(horizons) - 1)
            grad = torch.autograd.grad(target, x_clone, retain_graph=(not is_last))[0]
            with torch.no_grad():
                saliency = (grad * x_clone).squeeze(0).abs().mean(dim=0).cpu().numpy()
                top_indices = np.argsort(saliency)[::-1][:5]
                results[h] = [STATE_FEATURE_NAMES[i] for i in top_indices]
        return results

    def _compute_lightweight_saliency(
        self, x_scaled_tensor: torch.Tensor, horizon: int = 1
    ) -> List[str]:
        """Fast input gradient x input saliency for lightweight explainability."""
        return self._compute_lightweight_saliency_all(x_scaled_tensor, [horizon])[horizon]

    def _compute_full_integrated_gradients(
        self, x_scaled_tensor: torch.Tensor, horizon: int = 1
    ) -> Dict[str, Any]:
        """Full 50-step Integrated Gradients attribution using train-partition baseline."""
        if self.baseline_manager is not None:
            base_arr = self.baseline_manager.get_baseline_sequence(seq_len=10, scaled=True)
            baseline_tensor = torch.tensor(base_arr, dtype=torch.float32, device=self.device)
        else:
            baseline_tensor = torch.zeros_like(x_scaled_tensor)

        ig_result = self.ig_explainer.attribute(
            input_tensor=x_scaled_tensor,
            baseline_tensor=baseline_tensor,
            horizon=horizon,
            target_type="attack",
            steps=50,
        )

        matrix = ig_result.get("attribution_matrix", ig_result.get("attribution")) # (10, 22)
        feature_attr = np.mean(np.abs(matrix), axis=0) # (22,)
        window_attr = np.mean(np.abs(matrix), axis=1) # (10,)

        top_feat_indices = np.argsort(feature_attr)[::-1][:5]
        top_features = [STATE_FEATURE_NAMES[idx] for idx in top_feat_indices]

        return {
            "top_features": top_features,
            "feature_attribution_scores": {STATE_FEATURE_NAMES[i]: float(feature_attr[i]) for i in top_feat_indices},
            "window_attribution_scores": [float(w) for w in window_attr],
            "completeness_delta": float(ig_result.get("completeness", {}).get("absolute_error", 0.0)),
        }

    def predict_single_sequence(
        self,
        x_raw: np.ndarray,
        explain_mode: Optional[str] = None,
        enrich_mode: Optional[str] = None,
        forecast_id: Optional[str] = None,
        origin_window_index: int = 0,
    ) -> Dict[str, Any]:
        """
        Run complete inference on a single unscaled sequence array of shape (10, 22).
        """
        start_time = time.perf_counter()
        expl_mode = explain_mode or self.config.explain_mode
        enr_mode = enrich_mode or self.config.enrich_mode
        fid = forecast_id or f"NEXUS-FC-{uuid.uuid4().hex[:8].upper()}"

        if x_raw.shape != (10, 22):
            raise ValidationError(f"Expected shape (10, 22), got {x_raw.shape}")

        # 1. Scale input sequence
        # Reshape to (10, 22) for standard transform
        x_scaled = self.scaler.transform(x_raw).astype(np.float32)
        x_tensor = torch.tensor(x_scaled, dtype=torch.float32, device=self.device).unsqueeze(0) # (1, 10, 22)

        # 2. Forward pass through frozen GRU World Model
        with torch.no_grad():
            outputs = self.model(x_tensor)

        horizons_output = {}
        all_predicted_attacks = []
        all_probabilities = []
        trajectory = []

        # We will collect explanation features across horizons
        horizon_top_features: Dict[int, List[str]] = {}

        # 3. Process each horizon
        for h in self.config.horizons:
            # Future state regression
            pred_state_scaled = outputs["state"][h].cpu().numpy()[0] # (22,)
            pred_state_physical = self.scaler.inverse_transform(pred_state_scaled.reshape(1, -1))[0]

            # Raw attack logit & Platt calibration
            raw_attack_logit = float(outputs["attack"][h].cpu().numpy()[0])
            calibrated_prob = self.calibrate_logit(raw_attack_logit, horizon=h)
            predicted_attack = bool(calibrated_prob >= self.config.operational_threshold)

            all_predicted_attacks.append(predicted_attack)
            all_probabilities.append(calibrated_prob)

            # Stage prediction
            stage_logits = outputs["stage"][h].cpu().numpy()[0] # (9,)
            stage_probs = np.exp(stage_logits) / np.sum(np.exp(stage_logits))
            pred_stage_idx = int(np.argmax(stage_probs))
            pred_stage_name = IDX_TO_STAGE.get(pred_stage_idx, "BENIGN")
            stage_confidence = float(stage_probs[pred_stage_idx])

            # If model predicts no attack at threshold theta*=0.45, stage defaults to BENIGN
            if not predicted_attack:
                pred_stage_name = "BENIGN"

            trajectory.append(pred_stage_name)

            horizons_output[f"h{h}"] = {
                "horizon_step": h,
                "horizon_seconds": h * self.config.step_size_seconds,
                "raw_attack_logit": round(raw_attack_logit, 4),
                "calibrated_attack_prob": round(calibrated_prob, 4),
                "predicted_attack": predicted_attack,
                "threshold": self.config.operational_threshold,
                "predicted_stage": pred_stage_name,
                "stage_confidence": round(stage_confidence, 4),
                "stage_probabilities": {
                    STAGE_VOCABULARY[i]: round(float(stage_probs[i]), 4)
                    for i in range(len(STAGE_VOCABULARY))
                },
                "forecasted_state_physical": {
                    STATE_FEATURE_NAMES[i]: round(float(pred_state_physical[i]), 4)
                    for i in range(len(STATE_FEATURE_NAMES))
                }
            }

        # 4. Explainability attribution (Phase 17)
        if expl_mode == "lightweight":
            all_saliency = self._compute_lightweight_saliency_all(x_tensor, self.config.horizons)
            for h in self.config.horizons:
                h_key = f"h{h}"
                top_feats = all_saliency.get(h, [])
                horizon_top_features[h] = top_feats
                horizons_output[h_key]["explanation"] = {
                    "mode": "lightweight",
                    "top_contributing_features": top_feats,
                }
        elif expl_mode == "full":
            for h in self.config.horizons:
                h_key = f"h{h}"
                full_expl = self._compute_full_integrated_gradients(x_tensor, horizon=h)
                horizon_top_features[h] = full_expl["top_features"]
                horizons_output[h_key]["explanation"] = {
                    "mode": "full_integrated_gradients",
                    **full_expl
                }

        # 5. Knowledge Enrichment (Phase 18)
        if enr_mode != "none":
            for h in self.config.horizons:
                h_key = f"h{h}"
                h_info = horizons_output[h_key]
                top_feats = horizon_top_features.get(h, [])

                enriched_h = self.forecast_enricher.enrich_horizon(
                    horizon_step=h,
                    horizon_seconds=h_info["horizon_seconds"],
                    predicted_attack=h_info["predicted_attack"],
                    calibrated_attack_prob=h_info["calibrated_attack_prob"],
                    predicted_stage=h_info["predicted_stage"],
                    stage_confidence=h_info["stage_confidence"],
                    top_features=top_feats,
                )

                if enr_mode == "attack":
                    horizons_output[h_key]["enrichment"] = {
                        "attack_techniques": [t.to_dict() for t in enriched_h.attack_techniques],
                        "unresolved_review_items": enriched_h.unresolved_review_items,
                    }
                elif enr_mode == "full":
                    horizons_output[h_key]["enrichment"] = {
                        "attack_techniques": [t.to_dict() for t in enriched_h.attack_techniques],
                        "capec_patterns": [c.to_dict() for c in enriched_h.capec_patterns],
                        "evidence_categories": enriched_h.top_evidence_categories,
                        "unresolved_review_items": enriched_h.unresolved_review_items,
                    }

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        max_prob = max(all_probabilities)
        threat_level = "BENIGN"
        if max_prob >= 0.85:
            threat_level = "CRITICAL"
        elif max_prob >= 0.65:
            threat_level = "HIGH"
        elif max_prob >= self.config.operational_threshold:
            threat_level = "ELEVATED"

        return {
            "forecast_id": fid,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "device": str(self.device),
            "execution_time_ms": round(elapsed_ms, 2),
            "origin_window_index": origin_window_index,
            "horizons": horizons_output,
            "summary": {
                "overall_attack_forecasted": any(all_predicted_attacks),
                "max_attack_prob": round(float(max_prob), 4),
                "predicted_trajectory": trajectory,
                "threat_level": threat_level,
                "operational_threshold": self.config.operational_threshold,
            },
            "meta": {
                "pipeline_version": "1.0.0",
                "phase": "PHASE_19_OFFLINE_INFERENCE",
                "air_gapped_guarantee": True,
                "deterministic": True,
            }
        }

    def predict(
        self,
        input_data: Union[np.ndarray, pd.DataFrame, str],
        explain_mode: Optional[str] = None,
        enrich_mode: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Unified prediction entry point accepting file path, DataFrame, or numpy array.
        """
        if isinstance(input_data, str):
            if not os.path.exists(input_data):
                raise FileNotFoundError(f"Input file not found: {input_data}")
            if input_data.endswith(".parquet"):
                df = pd.read_parquet(input_data)
                arr = InputValidator.extract_sequences_from_dataframe(df)
            elif input_data.endswith(".csv"):
                df = pd.read_csv(input_data)
                arr = InputValidator.extract_sequences_from_dataframe(df)
            else:
                raise ValueError(f"Unsupported file format: {input_data}. Expected .parquet or .csv")
        elif isinstance(input_data, pd.DataFrame):
            arr = InputValidator.extract_sequences_from_dataframe(input_data)
        elif isinstance(input_data, np.ndarray):
            arr = InputValidator.validate_sequence_array(input_data)
        else:
            raise TypeError(f"Unsupported input type: {type(input_data)}")

        results = []
        for i in range(arr.shape[0]):
            res = self.predict_single_sequence(
                x_raw=arr[i],
                explain_mode=explain_mode,
                enrich_mode=enrich_mode,
                origin_window_index=i,
            )
            results.append(res)

        return results
