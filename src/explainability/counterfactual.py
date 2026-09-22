"""
Counterfactual Sensitivity and Controlled Ablation Analyzer (Phase 17).
Evaluates model sensitivity under controlled in-memory perturbations:
1. Feature Perturbation: Replaces top influential features with baseline reference state.
2. Temporal Ablation: Masks influential historical timesteps with baseline state vector.

Mandatory Principle:
- Does NOT alter underlying datasets.
- Labelled strictly as 'model sensitivity under controlled perturbation', NEVER 'causal effect'.
- Cross-checks Integrated Gradients attribution signs with empirical perturbation shifts.
"""

import torch
import numpy as np
from typing import Dict, List, Any, Optional

from src.world_model.dataset import STATE_FEATURE_NAMES
from src.explainability.baseline import BaselineManager


class CounterfactualAnalyzer:
    def __init__(
        self,
        model: torch.nn.Module,
        baseline_manager: BaselineManager,
        device: torch.device,
        calibrator: Optional[Any] = None
    ):
        self.model = model
        self.baseline_manager = baseline_manager
        self.device = device
        self.calibrator = calibrator
        self.model.eval()

    def analyze_feature_sensitivity(
        self,
        input_tensor: torch.Tensor,         # Shape: (1, 10, 22)
        top_features: List[Dict[str, Any]], # List from AttributionDecomposer
        horizon: int = 1,
        top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Perturbs the top-k influential features by replacing each with its benign baseline value.
        """
        if input_tensor.ndim == 2:
            input_tensor = input_tensor.unsqueeze(0)

        x_orig = input_tensor.to(self.device).float()
        baseline_vec = self.baseline_manager.benign_median_scaled # shape: (22,)

        # Baseline original forward pass
        with torch.no_grad():
            out_orig = self.model(x_orig)
            orig_logit = float(out_orig["attack"][horizon].cpu().numpy()[0])
            orig_raw_prob = float(1.0 / (1.0 + np.exp(-orig_logit)))
            if self.calibrator is not None and self.calibrator.is_fitted:
                orig_cal_prob = float(self.calibrator.calibrate(np.array([orig_logit]))[0])
            else:
                orig_cal_prob = orig_raw_prob

        results = []
        for feat_item in top_features[:top_k]:
            feat_name = feat_item["feature"]
            feat_idx = feat_item["feature_index"]
            base_val = float(baseline_vec[feat_idx])

            # In-memory clone and perturbation
            x_pert = x_orig.clone()
            x_pert[0, :, feat_idx] = base_val

            with torch.no_grad():
                out_pert = self.model(x_pert)
                pert_logit = float(out_pert["attack"][horizon].cpu().numpy()[0])
                pert_raw_prob = float(1.0 / (1.0 + np.exp(-pert_logit)))
                if self.calibrator is not None and self.calibrator.is_fitted:
                    pert_cal_prob = float(self.calibrator.calibrate(np.array([pert_logit]))[0])
                else:
                    pert_cal_prob = pert_raw_prob

            delta_logit = pert_logit - orig_logit
            delta_cal_prob = pert_cal_prob - orig_cal_prob

            # Consistency check: If feature was attack-supporting (IG > 0),
            # resetting it to benign baseline should suppress attack (delta_logit <= 0)
            expected_direction = feat_item["direction"]
            is_consistent = (expected_direction == "attack_supporting" and delta_logit <= 0) or \
                            (expected_direction == "attack_suppressing" and delta_logit >= 0)

            results.append({
                "perturbation_type": "feature_ablation",
                "feature": feat_name,
                "feature_index": feat_idx,
                "original_logit": round(orig_logit, 4),
                "perturbed_logit": round(pert_logit, 4),
                "delta_logit": round(delta_logit, 4),
                "original_calibrated_probability": round(orig_cal_prob, 4),
                "perturbed_calibrated_probability": round(pert_cal_prob, 4),
                "delta_calibrated_probability": round(delta_cal_prob, 4),
                "attributed_direction": expected_direction,
                "perturbation_consistent_with_ig": bool(is_consistent),
                "methodological_label": "model sensitivity under controlled feature perturbation"
            })

        return results

    def analyze_temporal_ablation(
        self,
        input_tensor: torch.Tensor,          # Shape: (1, 10, 22)
        top_timesteps: List[Dict[str, Any]], # List from AttributionDecomposer
        horizon: int = 1,
        top_k: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Ablates top influential historical timesteps by replacing them with the benign baseline state vector.
        """
        if input_tensor.ndim == 2:
            input_tensor = input_tensor.unsqueeze(0)

        x_orig = input_tensor.to(self.device).float()
        baseline_vec_tensor = torch.tensor(
            self.baseline_manager.benign_median_scaled, dtype=torch.float32, device=self.device
        ) # (22,)

        with torch.no_grad():
            out_orig = self.model(x_orig)
            orig_logit = float(out_orig["attack"][horizon].cpu().numpy()[0])
            orig_raw_prob = float(1.0 / (1.0 + np.exp(-orig_logit)))
            if self.calibrator is not None and self.calibrator.is_fitted:
                orig_cal_prob = float(self.calibrator.calibrate(np.array([orig_logit]))[0])
            else:
                orig_cal_prob = orig_raw_prob

        # Sort timesteps by absolute attribution descending
        sorted_steps = sorted(top_timesteps, key=lambda r: r["absolute_attribution"], reverse=True)

        results = []
        for step_item in sorted_steps[:top_k]:
            t_idx = step_item["timestep_index"]
            pos_label = step_item["relative_position"]

            # In-memory clone and temporal masking
            x_pert = x_orig.clone()
            x_pert[0, t_idx, :] = baseline_vec_tensor

            with torch.no_grad():
                out_pert = self.model(x_pert)
                pert_logit = float(out_pert["attack"][horizon].cpu().numpy()[0])
                pert_raw_prob = float(1.0 / (1.0 + np.exp(-pert_logit)))
                if self.calibrator is not None and self.calibrator.is_fitted:
                    pert_cal_prob = float(self.calibrator.calibrate(np.array([pert_logit]))[0])
                else:
                    pert_cal_prob = pert_raw_prob

            delta_logit = pert_logit - orig_logit
            delta_cal_prob = pert_cal_prob - orig_cal_prob

            expected_direction = step_item["direction"]
            is_consistent = (expected_direction == "attack_supporting" and delta_logit <= 0) or \
                            (expected_direction == "attack_suppressing" and delta_logit >= 0)

            results.append({
                "perturbation_type": "temporal_window_ablation",
                "timestep_index": t_idx,
                "relative_position": pos_label,
                "original_logit": round(orig_logit, 4),
                "perturbed_logit": round(pert_logit, 4),
                "delta_logit": round(delta_logit, 4),
                "original_calibrated_probability": round(orig_cal_prob, 4),
                "perturbed_calibrated_probability": round(pert_cal_prob, 4),
                "delta_calibrated_probability": round(delta_cal_prob, 4),
                "attributed_direction": expected_direction,
                "perturbation_consistent_with_ig": bool(is_consistent),
                "methodological_label": "model sensitivity under controlled temporal ablation"
            })

        return results
