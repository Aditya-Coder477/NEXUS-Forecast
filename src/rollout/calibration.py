"""
Probability Calibration and Reliability Assessment Module for Phase 16.
Implements Platt scaling (Logistic Regression on validation logits),
computes Brier score and Expected Calibration Error (ECE),
and generates reliability diagram curves.
"""

import numpy as np
from typing import Dict, Any, Tuple, Optional
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import calibration_curve

class ProbabilityCalibrator:
    def __init__(self):
        self.calibrator = LogisticRegression(C=1.0, solver="lbfgs", max_iter=1000)
        self.is_fitted = False

    def fit(self, val_logits: np.ndarray, val_labels: np.ndarray):
        """
        Fits Platt scaling model strictly on validation logits.
        """
        # val_logits: shape (N,)
        X_val = val_logits.reshape(-1, 1)
        self.calibrator.fit(X_val, val_labels)
        self.is_fitted = True
        return self

    def calibrate(self, logits: np.ndarray) -> np.ndarray:
        """
        Transforms raw logits into calibrated probabilities.
        """
        if not self.is_fitted:
            # Fallback to standard sigmoid
            return 1.0 / (1.0 + np.exp(-logits))
        X = logits.reshape(-1, 1)
        probs = self.calibrator.predict_proba(X)[:, 1]
        return probs

    @staticmethod
    def compute_brier_score(y_true: np.ndarray, y_prob: np.ndarray) -> float:
        """Computes Brier Score: Mean squared error of probability predictions."""
        return float(np.mean((y_prob - y_true) ** 2))

    @staticmethod
    def compute_ece(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> float:
        """
        Computes Expected Calibration Error (ECE) across n_bins.
        """
        bin_boundaries = np.linspace(0, 1, n_bins + 1)
        bin_lowers = bin_boundaries[:-1]
        bin_uppers = bin_boundaries[1:]

        ece = 0.0
        n_samples = len(y_true)

        for bin_lower, bin_upper in zip(bin_lowers, bin_uppers):
            # Bin mask
            in_bin = (y_prob > bin_lower) & (y_prob <= bin_upper)
            prop_in_bin = np.mean(in_bin)
            if prop_in_bin > 0:
                accuracy_in_bin = np.mean(y_true[in_bin])
                avg_confidence_in_bin = np.mean(y_prob[in_bin])
                ece += np.abs(avg_confidence_in_bin - accuracy_in_bin) * prop_in_bin

        return float(ece)

    @staticmethod
    def get_calibration_curve(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> Tuple[np.ndarray, np.ndarray]:
        """Computes calibration curve (fraction of positives vs mean predicted value)."""
        prob_true, prob_pred = calibration_curve(y_true, y_prob, n_bins=n_bins, strategy="uniform")
        return prob_true, prob_pred
