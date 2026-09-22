"""
Evaluator module for Phase 13 Logistic Regression Baseline.
Computes:
- Required metrics: F1 (Positive class = Attack), Precision, Recall, False Positive Rate (FP / (FP + TN)).
- Additional metrics: Accuracy, Specificity (TN / (TN + FP)), ROC-AUC, PR-AUC.
- Full confusion matrix: TN, FP, FN, TP.
"""

import numpy as np
from typing import Dict, Any, Optional
from sklearn.metrics import (
    f1_score,
    precision_score,
    recall_score,
    accuracy_score,
    confusion_matrix,
    roc_auc_score,
    precision_recall_curve,
    auc
)

class BaselineEvaluator:
    def __init__(self, threshold: float = 0.50):
        self.threshold = threshold

    def evaluate(
        self, y_true: np.ndarray, y_proba: np.ndarray, threshold: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Evaluates predictions against true binary targets.
        y_proba: 1D array of predicted probabilities for attack (class 1).
        """
        th = threshold if threshold is not None else self.threshold
        y_pred = (y_proba >= th).astype(int)

        # Confusion Matrix:
        # labels=[0, 1] ensures 2x2 matrix even if one class is missing
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()

        # Required Metric 1: F1 Score (Attack class)
        f1 = float(f1_score(y_true, y_pred, pos_label=1, zero_division=0))

        # Required Metric 2: Precision (Attack class)
        precision = float(precision_score(y_true, y_pred, pos_label=1, zero_division=0))

        # Required Metric 3: Recall (Attack class)
        recall = float(recall_score(y_true, y_pred, pos_label=1, zero_division=0))

        # Required Metric 4: False Positive Rate = FP / (FP + TN)
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fpr_pct = round(fpr * 100.0, 2)

        # Additional Metric: Accuracy
        acc = float(accuracy_score(y_true, y_pred))

        # Additional Metric: Specificity = TN / (TN + FP) = 1 - FPR
        specificity = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0

        # Additional Metric: ROC-AUC
        try:
            if len(np.unique(y_true)) > 1:
                roc_auc = float(roc_auc_score(y_true, y_proba))
            else:
                roc_auc = None
        except Exception:
            roc_auc = None

        # Additional Metric: PR-AUC
        try:
            if len(np.unique(y_true)) > 1:
                p_curve, r_curve, _ = precision_recall_curve(y_true, y_proba, pos_label=1)
                pr_auc = float(auc(r_curve, p_curve))
            else:
                pr_auc = None
        except Exception:
            pr_auc = None

        return {
            "threshold": th,
            "f1": round(f1, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "false_positive_rate": round(fpr, 4),
            "false_positive_rate_percent": fpr_pct,
            "accuracy": round(acc, 4),
            "specificity": round(specificity, 4),
            "roc_auc": round(roc_auc, 4) if roc_auc is not None else "N/A",
            "pr_auc": round(pr_auc, 4) if pr_auc is not None else "N/A",
            "confusion_matrix": {
                "tn": int(tn),
                "fp": int(fp),
                "fn": int(fn),
                "tp": int(tp)
            },
            "sample_counts": {
                "total": int(len(y_true)),
                "actual_benign": int(tn + fp),
                "actual_attack": int(fn + tp),
                "pred_benign": int(tn + fn),
                "pred_attack": int(fp + tp)
            }
        }
