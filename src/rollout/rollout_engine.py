"""
Autoregressive Rollout Engine for NEXUS-Forecast Phase 16.
Implements:
1. Multi-step recursive state rollout (S_t -> \hat{S}_{t+1} -> ... -> \hat{S}_{t+6})
2. Step-by-step attack likelihood and stage trajectory evaluation
3. Comparative error analysis: Direct Horizon vs Autoregressive Rollout
4. Feature-level MAE and RMSE tracking
5. Generation of standardized JSON forecast objects
"""

import os
import torch
import numpy as np
import pandas as pd
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from sklearn.metrics import mean_absolute_error, mean_squared_error

from src.world_model.dataset import STATE_FEATURE_NAMES, STAGE_VOCABULARY
from src.rollout.calibration import ProbabilityCalibrator

HORIZON_MAP = {1: "+30s", 2: "+60s", 3: "+90s", 4: "+120s", 5: "+150s", 6: "+180s"}
STAGE_NAMES = {idx: name for idx, name in enumerate(STAGE_VOCABULARY)}

class GRURolloutEngine:
    def __init__(
        self,
        model: torch.nn.Module,
        scaler: Any,
        device: torch.device,
        calibrator: Optional[ProbabilityCalibrator] = None,
        operating_threshold: float = 0.50
    ):
        self.model = model
        self.scaler = scaler
        self.device = device
        self.calibrator = calibrator
        self.operating_threshold = operating_threshold
        self.model.eval()

    def set_calibrator(self, calibrator: ProbabilityCalibrator):
        self.calibrator = calibrator

    def set_operating_threshold(self, threshold: float):
        self.operating_threshold = threshold

    def rollout_trajectory(
        self,
        initial_seq: np.ndarray, # Shape: (1, 10, 22) or (10, 22)
        rollout_steps: int = 6
    ) -> Dict[str, Any]:
        """
        Performs pure autoregressive rollout up to `rollout_steps`.
        At each step tau in 1..rollout_steps:
          - Uses S_{t+tau-1} as input to predict \hat{S}_{t+tau} via K=1 head.
          - Updates rolling buffer by dropping oldest window and appending \hat{S}_{t+tau}.
          - Evaluates attack likelihood and stage classification via K=1 head on the simulated buffer.
        """
        if initial_seq.ndim == 2:
            initial_seq = np.expand_dims(initial_seq, axis=0)

        buffer = torch.tensor(initial_seq, dtype=torch.float32, device=self.device)
        
        forecasted_states_norm = {}
        forecasted_states_orig = {}
        forecasted_attack_likelihood = {}
        forecasted_stage_trajectory = {}

        with torch.no_grad():
            for step in range(1, rollout_steps + 1):
                h_key = HORIZON_MAP.get(step, f"+{step * 30}s")
                outputs = self.model(buffer)

                # State prediction via K=1 head
                next_state_tensor = outputs["state"][1] # (1, 22)
                next_state_norm = next_state_tensor.cpu().numpy()[0] # (22,)
                next_state_orig = self.scaler.inverse_transform(next_state_norm.reshape(1, -1))[0]

                forecasted_states_norm[h_key] = next_state_norm
                forecasted_states_orig[h_key] = {
                    feat: round(float(val), 4) for feat, val in zip(STATE_FEATURE_NAMES, next_state_orig)
                }

                # Attack likelihood via K=1 head
                attack_logit = float(outputs["attack"][1].cpu().numpy()[0])
                raw_prob = float(1.0 / (1.0 + np.exp(-attack_logit)))
                
                if self.calibrator is not None and self.calibrator.is_fitted:
                    cal_prob = float(self.calibrator.calibrate(np.array([attack_logit]))[0])
                else:
                    cal_prob = raw_prob

                attack_pred = int(cal_prob >= self.operating_threshold)
                forecasted_attack_likelihood[h_key] = {
                    "raw_probability": round(raw_prob, 4),
                    "calibrated_probability": round(cal_prob, 4),
                    "attack_predicted": attack_pred,
                    "threshold_applied": self.operating_threshold
                }

                # Stage trajectory via K=1 head
                stage_logits = outputs["stage"][1].cpu().numpy()[0] # (9,)
                stage_probs = np.exp(stage_logits - np.max(stage_logits))
                stage_probs = stage_probs / np.sum(stage_probs)
                pred_stage_idx = int(np.argmax(stage_probs))
                pred_stage_name = STAGE_NAMES.get(pred_stage_idx, "Unknown")
                pred_stage_conf = float(stage_probs[pred_stage_idx])

                forecasted_stage_trajectory[h_key] = {
                    "stage_id": pred_stage_idx,
                    "stage_name": pred_stage_name,
                    "confidence": round(pred_stage_conf, 4),
                    "all_stage_probabilities": {
                        STAGE_NAMES.get(i, f"stage_{i}"): round(float(p), 4)
                        for i, p in enumerate(stage_probs)
                    }
                }

                # Pure Autoregressive Rollout update: drop S_{t-9}, append \hat{S}_{t+tau}
                next_state_unsqueezed = next_state_tensor.unsqueeze(1) # (1, 1, 22)
                buffer = torch.cat([buffer[:, 1:, :], next_state_unsqueezed], dim=1)

        # Summary across trajectory
        all_probs = [v["calibrated_probability"] for v in forecasted_attack_likelihood.values()]
        max_prob = max(all_probs)
        escalation = any(v["attack_predicted"] == 1 for v in forecasted_attack_likelihood.values())
        first_esc = next((k for k, v in forecasted_attack_likelihood.items() if v["attack_predicted"] == 1), "None")
        
        stages = [v["stage_name"] for v in forecasted_stage_trajectory.values()]
        # Dominant stage (most frequent non-benign stage if attack escalation occurs)
        non_benign = [s for s in stages if s.lower() != "benign"]
        if non_benign:
            dominant_stage = max(set(non_benign), key=non_benign.count)
        else:
            dominant_stage = stages[0]

        summary = {
            "escalation_detected": escalation,
            "max_attack_likelihood": round(float(max_prob), 4),
            "first_escalation_horizon": first_esc,
            "dominant_stage": dominant_stage
        }

        return {
            "forecasted_states_normalized": forecasted_states_norm,
            "forecasted_states": forecasted_states_orig,
            "forecasted_attack_likelihood": forecasted_attack_likelihood,
            "forecasted_stage_trajectory": forecasted_stage_trajectory,
            "overall_trajectory_summary": summary
        }

    def generate_standard_forecast_object(
        self,
        initial_seq: np.ndarray,
        metadata: Dict[str, Any],
        rollout_steps: int = 6
    ) -> Dict[str, Any]:
        """
        Produces the standardized JSON forecast object conforming to Section 18 of Phase 16 prompt.
        """
        trajectory_res = self.rollout_trajectory(initial_seq, rollout_steps=rollout_steps)
        
        # Unscale current state S_t (the last window in initial_seq)
        s_t_norm = initial_seq[0, -1, :] if initial_seq.ndim == 3 else initial_seq[-1, :]
        s_t_orig = self.scaler.inverse_transform(s_t_norm.reshape(1, -1))[0]
        current_state_dict = {
            feat: round(float(val), 4) for feat, val in zip(STATE_FEATURE_NAMES, s_t_orig)
        }

        forecast_obj = {
            "prediction_timestamp": datetime.now(timezone.utc).isoformat(),
            "prediction_origin": metadata.get("prediction_origin", "t"),
            "dataset": metadata.get("dataset", "Unknown"),
            "scenario_id": metadata.get("scenario_id", "Unknown"),
            "current_attack_flag": int(metadata.get("current_attack_flag", 0)),
            "current_stage": metadata.get("current_stage", "Benign"),
            "forecast_horizons_seconds": [30 * s for s in range(1, rollout_steps + 1)],
            "current_state": current_state_dict,
            "forecasted_states": trajectory_res["forecasted_states"],
            "forecasted_attack_likelihood": trajectory_res["forecasted_attack_likelihood"],
            "forecasted_stage_trajectory": trajectory_res["forecasted_stage_trajectory"],
            "overall_trajectory_summary": trajectory_res["overall_trajectory_summary"]
        }
        return forecast_obj

    def evaluate_rollout_vs_direct(
        self,
        X_test: np.ndarray,
        y_test_states: Dict[int, np.ndarray],
        horizons: List[int] = [1, 3, 6],
        sample_size: int = 500
    ) -> Tuple[Dict[str, Any], pd.DataFrame]:
        """
        Compares Direct Horizon Prediction vs Autoregressive Rollout on test samples.
        Computes overall MAE/RMSE and per-feature MAE/RMSE across horizons.
        Returns:
          (summary_dict, feature_errors_df)
        """
        n_samples = min(len(X_test), sample_size)
        indices = np.random.RandomState(42).choice(len(X_test), n_samples, replace=False)

        direct_errors = {k: {"mae": [], "rmse": []} for k in horizons}
        rollout_errors = {k: {"mae": [], "rmse": []} for k in horizons}

        # Per feature accumulators: shape (n_samples, 22)
        direct_feat_diffs = {k: [] for k in horizons}
        rollout_feat_diffs = {k: [] for k in horizons}

        with torch.no_grad():
            for idx in indices:
                x_sample = X_test[idx:idx+1]
                x_tensor = torch.tensor(x_sample, dtype=torch.float32, device=self.device)

                # Direct prediction from multi-horizon heads
                direct_out = self.model(x_tensor)["state"]

                # Autoregressive rollout
                traj = self.rollout_trajectory(x_sample, rollout_steps=max(horizons))
                traj_norm = traj["forecasted_states_normalized"]

                for k in horizons:
                    actual = y_test_states[k][idx]
                    pred_direct = direct_out[k].cpu().numpy()[0]
                    h_key = HORIZON_MAP.get(k, f"+{k * 30}s")
                    pred_rollout = traj_norm[h_key]

                    # Absolute errors
                    diff_direct = np.abs(actual - pred_direct)
                    diff_rollout = np.abs(actual - pred_rollout)

                    direct_feat_diffs[k].append(diff_direct)
                    rollout_feat_diffs[k].append(diff_rollout)

                    direct_errors[k]["mae"].append(float(np.mean(diff_direct)))
                    direct_errors[k]["rmse"].append(float(np.sqrt(np.mean((actual - pred_direct) ** 2))))

                    rollout_errors[k]["mae"].append(float(np.mean(diff_rollout)))
                    rollout_errors[k]["rmse"].append(float(np.sqrt(np.mean((actual - pred_rollout) ** 2))))

        summary = {}
        for k in horizons:
            h_key = HORIZON_MAP.get(k, f"+{k * 30}s")
            dir_mae = float(np.mean(direct_errors[k]["mae"]))
            dir_rmse = float(np.mean(direct_errors[k]["rmse"]))
            roll_mae = float(np.mean(rollout_errors[k]["mae"]))
            roll_rmse = float(np.mean(rollout_errors[k]["rmse"]))

            summary[h_key] = {
                "horizon_k": k,
                "direct_mae": round(dir_mae, 4),
                "direct_rmse": round(dir_rmse, 4),
                "rollout_mae": round(roll_mae, 4),
                "rollout_rmse": round(roll_rmse, 4),
                "mae_delta": round(roll_mae - dir_mae, 4),
                "rmse_delta": round(roll_rmse - dir_rmse, 4)
            }

        # Construct per-feature errors table
        feature_rows = []
        for k in horizons:
            h_key = HORIZON_MAP.get(k, f"+{k * 30}s")
            d_diffs = np.array(direct_feat_diffs[k]) # (n_samples, 22)
            r_diffs = np.array(rollout_feat_diffs[k]) # (n_samples, 22)

            for feat_idx, feat_name in enumerate(STATE_FEATURE_NAMES):
                d_feat_mae = float(np.mean(d_diffs[:, feat_idx]))
                d_feat_rmse = float(np.sqrt(np.mean(d_diffs[:, feat_idx] ** 2)))
                r_feat_mae = float(np.mean(r_diffs[:, feat_idx]))
                r_feat_rmse = float(np.sqrt(np.mean(r_diffs[:, feat_idx] ** 2)))

                feature_rows.append({
                    "horizon": h_key,
                    "horizon_k": k,
                    "feature_name": feat_name,
                    "direct_mae": round(d_feat_mae, 4),
                    "direct_rmse": round(d_feat_rmse, 4),
                    "rollout_mae": round(r_feat_mae, 4),
                    "rollout_rmse": round(r_feat_rmse, 4),
                    "mae_delta": round(r_feat_mae - d_feat_mae, 4),
                    "rmse_delta": round(r_feat_rmse - d_feat_rmse, 4)
                })

        feature_errors_df = pd.DataFrame(feature_rows)
        return summary, feature_errors_df
