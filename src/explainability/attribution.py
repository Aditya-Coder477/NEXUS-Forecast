"""
Attribution Decomposition and Aggregation Module for Phase 17.
Decomposes 10x22 Integrated Gradients matrices into:
1. Feature-level attribution (signed, absolute, normalized, direction).
2. Temporal attribution (per-window signed, absolute, normalized, direction).
3. Feature x Time attribution matrix representation.
4. Global and dataset-wise attribution aggregators.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple

from src.world_model.dataset import STATE_FEATURE_NAMES

TIMESTEP_LABELS = [
    "T-270s (t-9)", "T-240s (t-8)", "T-210s (t-7)", "T-180s (t-6)", "T-150s (t-5)",
    "T-120s (t-4)", "T-90s (t-3)",  "T-60s (t-2)",  "T-30s (t-1)",  "T (t)"
]


class AttributionDecomposer:
    @staticmethod
    def decompose_feature_attribution(
        ig_matrix: np.ndarray,
        feature_names: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Aggregates attribution across the 10 timesteps for each feature.
        ig_matrix: shape (10, 22)
        """
        feats = feature_names or list(STATE_FEATURE_NAMES)
        # Sum signed attribution across timesteps: shape (22,)
        signed_attrs = np.sum(ig_matrix, axis=0)
        abs_attrs = np.abs(signed_attrs)
        total_abs = float(np.sum(abs_attrs)) + 1e-9

        records = []
        for idx, feat in enumerate(feats):
            s_val = float(signed_attrs[idx])
            a_val = float(abs_attrs[idx])
            norm_imp = a_val / total_abs
            direction = "attack_supporting" if s_val > 0 else "attack_suppressing"

            records.append({
                "feature": feat,
                "feature_index": idx,
                "raw_attribution": round(s_val, 6),
                "absolute_attribution": round(a_val, 6),
                "normalized_importance": round(float(norm_imp), 6),
                "direction": direction
            })

        # Sort by absolute attribution descending
        records.sort(key=lambda r: r["absolute_attribution"], reverse=True)
        return records

    @staticmethod
    def decompose_temporal_attribution(
        ig_matrix: np.ndarray,
        window_timestamps: Optional[List[Tuple[str, str]]] = None
    ) -> List[Dict[str, Any]]:
        """
        Aggregates attribution across the 22 features for each of the 10 timesteps.
        ig_matrix: shape (10, 22)
        """
        # Sum signed attribution across features for each timestep: shape (10,)
        signed_time = np.sum(ig_matrix, axis=1)
        abs_time = np.abs(signed_time)
        total_abs = float(np.sum(abs_time)) + 1e-9

        records = []
        for t_idx in range(10):
            s_val = float(signed_time[t_idx])
            a_val = float(abs_time[t_idx])
            norm_imp = a_val / total_abs
            direction = "attack_supporting" if s_val > 0 else "attack_suppressing"

            w_start = window_timestamps[t_idx][0] if window_timestamps else f"t-{9-t_idx}"
            w_end = window_timestamps[t_idx][1] if window_timestamps else f"t-{9-t_idx}+60s"

            records.append({
                "timestep_index": t_idx,
                "relative_position": TIMESTEP_LABELS[t_idx],
                "window_start": w_start,
                "window_end": w_end,
                "raw_attribution": round(s_val, 6),
                "absolute_attribution": round(a_val, 6),
                "normalized_importance": round(float(norm_imp), 6),
                "direction": direction
            })

        return records

    @staticmethod
    def get_feature_time_dataframe(
        ig_matrix: np.ndarray,
        feature_names: Optional[List[str]] = None
    ) -> pd.DataFrame:
        """
        Returns 10x22 attribution matrix as DataFrame with labelled index and columns.
        """
        feats = feature_names or list(STATE_FEATURE_NAMES)
        df = pd.DataFrame(ig_matrix, index=TIMESTEP_LABELS, columns=feats)
        return df

    @staticmethod
    def aggregate_global_importance(
        sample_feature_attributions: List[List[Dict[str, Any]]],
        feature_names: Optional[List[str]] = None
    ) -> pd.DataFrame:
        """
        Aggregates feature attribution across a collection of explained sequences.
        Computes mean signed, mean absolute, median absolute, and top-5 frequency.
        """
        feats = feature_names or list(STATE_FEATURE_NAMES)
        n_samples = len(sample_feature_attributions)
        if n_samples == 0:
            return pd.DataFrame()

        raw_records = {f: [] for f in feats}
        top5_counts = {f: 0 for f in feats}

        for sample_records in sample_feature_attributions:
            # Top 5 in this sample
            top5_feats = [r["feature"] for r in sample_records[:5]]
            for f in top5_feats:
                top5_counts[f] += 1

            for r in sample_records:
                raw_records[r["feature"]].append(r["raw_attribution"])

        summary = []
        for feat in feats:
            vals = np.array(raw_records[feat])
            abs_vals = np.abs(vals)
            mean_s = float(np.mean(vals))
            mean_a = float(np.mean(abs_vals))
            med_a = float(np.median(abs_vals))
            top_freq = float(top5_counts[feat] / n_samples)

            summary.append({
                "feature": feat,
                "mean_signed_attribution": round(mean_s, 6),
                "mean_absolute_attribution": round(mean_a, 6),
                "median_absolute_attribution": round(med_a, 6),
                "top5_frequency": round(top_freq, 4),
                "overall_direction": "attack_supporting" if mean_s > 0 else "attack_suppressing"
            })

        df = pd.DataFrame(summary).sort_values("mean_absolute_attribution", ascending=False).reset_index(drop=True)
        total_mean_abs = df["mean_absolute_attribution"].sum() + 1e-9
        df["normalized_importance"] = (df["mean_absolute_attribution"] / total_mean_abs).round(6)
        return df
