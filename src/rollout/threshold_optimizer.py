"""
Threshold Optimizer and Metric Grid Search for Phase 16.
Evaluates operating thresholds from 0.10 to 0.90 on validation data,
computes precision, recall, F1, FPR, TPR, specificity, and selects the frozen threshold.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple, Optional
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, accuracy_score

class ThresholdOptimizer:
    def __init__(self, thresholds: Optional[List[float]] = None):
        self.thresholds = thresholds or [round(t, 2) for t in np.arange(0.10, 0.95, 0.05)]

    def evaluate_threshold_grid(self, y_true: np.ndarray, y_prob: np.ndarray) -> pd.DataFrame:
        """
        Computes comprehensive metrics across the threshold grid.
        """
        records = []
        for th in self.thresholds:
            y_pred = (y_prob >= th).astype(int)
            cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
            tn, fp, fn, tp = cm.ravel()

            prec = float(precision_score(y_true, y_pred, pos_label=1, zero_division=0))
            rec = float(recall_score(y_true, y_pred, pos_label=1, zero_division=0))
            f1 = float(f1_score(y_true, y_pred, pos_label=1, zero_division=0))
            fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
            tpr = rec
            spec = float(tn / (fp + tn)) if (fp + tn) > 0 else 0.0
            acc = float(accuracy_score(y_true, y_pred))

            # Cybersecurity utility score: balances attack recall while penalizing false alarm rate
            utility = f1 - (0.5 * fpr)

            records.append({
                "threshold": th,
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1": round(f1, 4),
                "fpr": round(fpr, 4),
                "fpr_percent": round(fpr * 100.0, 2),
                "tpr": round(tpr, 4),
                "specificity": round(spec, 4),
                "accuracy": round(acc, 4),
                "utility": round(utility, 4),
                "tn": int(tn),
                "fp": int(fp),
                "fn": int(fn),
                "tp": int(tp)
            })

        return pd.DataFrame(records)

    def select_optimal_threshold(self, val_df: pd.DataFrame) -> float:
        """
        Selects the best threshold from validation evaluation.
        Criteria: highest utility score (F1 - 0.5 * FPR) subject to recall >= 0.70.
        """
        candidates = val_df[val_df["recall"] >= 0.70]
        if candidates.empty:
            candidates = val_df
        best_row = candidates.loc[candidates["utility"].idxmax()]
        return float(best_row["threshold"])
