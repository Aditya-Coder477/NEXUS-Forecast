"""
Evaluator module for Phase 14 World Model.
Computes:
1. Binary Attack Forecasting Metrics: F1, Precision, Recall, FPR, Accuracy, Confusion Matrices.
2. Future-State Forecasting Metrics: MAE, RMSE, R2 (overall and per-feature).
3. Stage Forecasting Metrics: Stage Accuracy, Macro F1, Weighted F1, Stage Confusion Matrix.
"""

import numpy as np
from typing import Dict, List, Any, Optional
from sklearn.metrics import (
    f1_score,
    precision_score,
    recall_score,
    accuracy_score,
    confusion_matrix,
    mean_absolute_error,
    mean_squared_error,
    r2_score
)

class WorldModelEvaluator:
    def __init__(
        self,
        forecast_horizons: List[int] = [1, 3, 6],
        threshold: float = 0.50,
        feature_names: Optional[List[str]] = None,
        stage_vocabulary: Optional[List[str]] = None
    ):
        self.forecast_horizons = forecast_horizons
        self.threshold = threshold
        self.feature_names = feature_names or []
        self.stage_vocabulary = stage_vocabulary or []

    def evaluate_attack(
        self,
        y_true: Dict[int, np.ndarray],
        y_probs: Dict[int, np.ndarray],
        threshold: Optional[float] = None
    ) -> Dict[int, Dict[str, Any]]:
        """Evaluates binary attack predictions across horizons."""
        th = threshold if threshold is not None else self.threshold
        results = {}

        for k in self.forecast_horizons:
            yt = y_true[k].astype(int)
            yp = (y_probs[k] >= th).astype(int)

            cm = confusion_matrix(yt, yp, labels=[0, 1])
            tn, fp, fn, tp = cm.ravel()

            f1 = float(f1_score(yt, yp, pos_label=1, zero_division=0))
            prec = float(precision_score(yt, yp, pos_label=1, zero_division=0))
            rec = float(recall_score(yt, yp, pos_label=1, zero_division=0))
            fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
            acc = float(accuracy_score(yt, yp))

            results[k] = {
                "threshold": th,
                "f1": round(f1, 4),
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "false_positive_rate": round(fpr, 4),
                "false_positive_rate_percent": round(fpr * 100.0, 2),
                "accuracy": round(acc, 4),
                "confusion_matrix": {
                    "tn": int(tn),
                    "fp": int(fp),
                    "fn": int(fn),
                    "tp": int(tp)
                },
                "counts": {
                    "total": int(len(yt)),
                    "actual_attack": int(fn + tp),
                    "actual_benign": int(tn + fp)
                }
            }

        return results

    def evaluate_states(
        self,
        y_true_states: Dict[int, np.ndarray],
        y_pred_states: Dict[int, np.ndarray]
    ) -> Dict[int, Dict[str, Any]]:
        """Evaluates future-state predictions across horizons."""
        results = {}

        for k in self.forecast_horizons:
            yt = y_true_states[k]
            yp = y_pred_states[k]

            mae = float(mean_absolute_error(yt, yp))
            rmse = float(np.sqrt(mean_squared_error(yt, yp)))
            try:
                r2 = float(r2_score(yt, yp))
            except Exception:
                r2 = 0.0

            # Per-feature breakdown
            per_feat = {}
            if self.feature_names and yt.shape[1] == len(self.feature_names):
                for f_idx, feat in enumerate(self.feature_names):
                    feat_mae = float(mean_absolute_error(yt[:, f_idx], yp[:, f_idx]))
                    feat_rmse = float(np.sqrt(mean_squared_error(yt[:, f_idx], yp[:, f_idx])))
                    per_feat[feat] = {
                        "mae": round(feat_mae, 4),
                        "rmse": round(feat_rmse, 4)
                    }

            results[k] = {
                "mae": round(mae, 4),
                "rmse": round(rmse, 4),
                "r2": round(r2, 4),
                "per_feature": per_feat
            }

        return results

    def evaluate_stages(
        self,
        y_true_stages: Dict[int, np.ndarray],
        y_pred_stages: Dict[int, np.ndarray]
    ) -> Dict[int, Dict[str, Any]]:
        """Evaluates attack-stage classifications across horizons."""
        results = {}

        for k in self.forecast_horizons:
            yt = y_true_stages[k]
            yp = y_pred_stages[k]

            acc = float(accuracy_score(yt, yp))
            macro_f1 = float(f1_score(yt, yp, average="macro", zero_division=0))
            weighted_f1 = float(f1_score(yt, yp, average="weighted", zero_division=0))

            results[k] = {
                "accuracy": round(acc, 4),
                "macro_f1": round(macro_f1, 4),
                "weighted_f1": round(weighted_f1, 4)
            }

        return results
