"""
Baseline Manager for NEXUS-Forecast Explainability (Phase 17).
Strict Anti-Leakage Guarantee: All baseline distributions and reference vectors
are computed EXCLUSIVELY from the TRAIN partition. Zero validation or test data is used.

Computes:
1. Benign-sequence median baseline (primary semantic reference for normal network traffic).
2. Robust distribution statistics per feature: Median, Mean, Std, P95, P25, P75, IQR.
3. Baseline deviation calculators (P95 exceedance, robust IQR deviation, Z-score).
"""

import os
import json
import numpy as np
import pandas as pd
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple

from src.world_model.dataset import STATE_FEATURE_NAMES, extract_temporal_arrays


class BaselineManager:
    def __init__(self, scaler: Any = None):
        self.scaler = scaler
        self.is_fitted = False
        self.stats = {}
        self.metadata = {}
        self.benign_median_unscaled = None
        self.benign_median_scaled = None
        self.feature_names = list(STATE_FEATURE_NAMES)

    def fit(self, train_df: pd.DataFrame, scaler: Optional[Any] = None) -> "BaselineManager":
        """
        Fits baseline reference vectors and distribution statistics strictly on the TRAIN partition.
        """
        if scaler is not None:
            self.scaler = scaler

        if self.scaler is None:
            raise ValueError("StandardScaler must be provided to BaselineManager.")

        # Ensure we only use TRAIN split
        train_df = train_df[train_df["split"] == "TRAIN"].copy()
        n_train = len(train_df)
        if n_train == 0:
            raise ValueError("Training DataFrame is empty! Anti-leakage error.")

        # Extract S_t features (the most recent historical state in the sequence)
        s_t_cols = [f"S_t_{feat}" for feat in self.feature_names]
        s_t_unscaled = train_df[s_t_cols].values # (N, 22)
        s_t_scaled = self.scaler.transform(s_t_unscaled) # (N, 22)

        # Separate benign training sequences
        benign_mask = (train_df["current_attack_flag"] == 0).values
        if np.sum(benign_mask) > 0:
            benign_unscaled = s_t_unscaled[benign_mask]
            benign_scaled = s_t_scaled[benign_mask]
            self.benign_median_unscaled = np.median(benign_unscaled, axis=0)
            self.benign_median_scaled = np.median(benign_scaled, axis=0)
        else:
            # Fallback to overall median if no benign sequences
            self.benign_median_unscaled = np.median(s_t_unscaled, axis=0)
            self.benign_median_scaled = np.median(s_t_scaled, axis=0)

        # Compute robust statistics per feature
        feature_stats = {}
        for idx, feat in enumerate(self.feature_names):
            vals = s_t_unscaled[:, idx]
            p25 = float(np.percentile(vals, 25))
            p50 = float(np.percentile(vals, 50))
            p75 = float(np.percentile(vals, 75))
            p95 = float(np.percentile(vals, 95))
            mean_val = float(np.mean(vals))
            std_val = float(np.std(vals))
            iqr_val = float(p75 - p25)

            feature_stats[feat] = {
                "index": idx,
                "benign_median_unscaled": float(self.benign_median_unscaled[idx]),
                "benign_median_scaled": float(self.benign_median_scaled[idx]),
                "train_mean": round(mean_val, 4),
                "train_std": round(std_val, 4),
                "train_median": round(p50, 4),
                "train_p25": round(p25, 4),
                "train_p75": round(p75, 4),
                "train_p95": round(p95, 4),
                "train_iqr": round(iqr_val, 4)
            }

        self.stats = feature_stats
        self.metadata = {
            "baseline_version": "1.0.0",
            "source_split": "TRAIN",
            "num_train_samples": int(n_train),
            "num_benign_train_samples": int(np.sum(benign_mask)),
            "feature_count": len(self.feature_names),
            "creation_timestamp": datetime.now(timezone.utc).isoformat(),
            "anti_leakage_guarantee": "Strictly fitted on TRAIN partition. Zero VAL/TEST data used."
        }
        self.is_fitted = True
        return self

    def get_baseline_sequence(
        self,
        seq_len: int = 10,
        scaled: bool = True
    ) -> np.ndarray:
        """
        Constructs a baseline sequence tensor X' of shape (1, seq_len, 22)
        by repeating the benign median state across all 10 timesteps.
        """
        if not self.is_fitted:
            raise ValueError("BaselineManager is not fitted yet.")

        vec = self.benign_median_scaled if scaled else self.benign_median_unscaled
        # Repeat across seq_len: shape (seq_len, 22)
        seq = np.tile(vec, (seq_len, 1))
        # Add batch dimension: (1, seq_len, 22)
        return np.expand_dims(seq, axis=0).astype(np.float32)

    def compute_deviation(
        self,
        feature_name: str,
        current_val: float
    ) -> Dict[str, Any]:
        """
        Evaluates the deviation of a feature value against the TRAIN baseline distribution.
        Uses robust IQR deviation and P95 exceedance to avoid Gaussian assumptions on skewed traffic.
        """
        if not self.is_fitted:
            raise ValueError("BaselineManager is not fitted yet.")

        feat_stat = self.stats[feature_name]
        median_val = feat_stat["train_median"]
        iqr_val = feat_stat["train_iqr"]
        mean_val = feat_stat["train_mean"]
        std_val = feat_stat["train_std"]
        p95_val = feat_stat["train_p95"]

        # Robust IQR deviation
        iqr_dev = (current_val - median_val) / (iqr_val + 1e-5)
        # Z-score (provided for reference, but flagged if skewed)
        z_score = (current_val - mean_val) / (std_val + 1e-5)
        p95_exceeded = bool(current_val > p95_val)

        return {
            "feature_name": feature_name,
            "current_value": round(float(current_val), 4),
            "baseline_median": median_val,
            "baseline_mean": mean_val,
            "baseline_std": std_val,
            "baseline_p95": p95_val,
            "baseline_iqr": iqr_val,
            "iqr_deviation": round(float(iqr_dev), 4),
            "z_score": round(float(z_score), 4),
            "p95_exceeded": p95_exceeded,
            "primary_metric": "iqr_deviation",
            "interpretation": (
                "Substantially elevated above baseline (P95 exceeded)"
                if p95_exceeded else
                ("Above baseline" if iqr_dev > 1.0 else "Within expected baseline bounds")
            )
        }

    def save(self, filepath: str = "models/explainability/baseline_statistics.json"):
        """Saves baseline metadata and distribution stats to JSON."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        export_data = {
            "metadata": self.metadata,
            "benign_median_unscaled": [float(x) for x in self.benign_median_unscaled],
            "benign_median_scaled": [float(x) for x in self.benign_median_scaled],
            "feature_statistics": self.stats
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2)

    def load(self, filepath: str = "models/explainability/baseline_statistics.json") -> "BaselineManager":
        """Loads baseline metadata and distribution stats from JSON."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.metadata = data["metadata"]
        self.benign_median_unscaled = np.array(data["benign_median_unscaled"], dtype=np.float64)
        self.benign_median_scaled = np.array(data["benign_median_scaled"], dtype=np.float64)
        self.stats = data["feature_statistics"]
        self.is_fitted = True
        return self
