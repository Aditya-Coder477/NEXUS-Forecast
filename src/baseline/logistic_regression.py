"""
Logistic Regression Baseline Model Wrapper for NEXUS-Forecast Phase 13.
Encapsulates:
- StandardScaler (fitted strictly on TRAIN data)
- LogisticRegression(class_weight="balanced", max_iter=2000, random_state=42)
- Thresholding and probability prediction
- Joblib artifact serialization
"""

import os
import joblib
import numpy as np
from typing import Dict, Any, Optional, Tuple
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression

class LogisticRegressionBaseline:
    def __init__(
        self,
        class_weight: str = "balanced",
        max_iter: int = 2000,
        random_state: int = 42,
        solver: str = "lbfgs",
        C: float = 1.0,
        threshold: float = 0.50
    ):
        self.class_weight = class_weight
        self.max_iter = max_iter
        self.random_state = random_state
        self.solver = solver
        self.C = C
        self.threshold = threshold

        self.scaler: Optional[StandardScaler] = None
        self.model: Optional[LogisticRegression] = None
        self.is_fitted = False

    def fit(self, X_train: np.ndarray, y_train: np.ndarray):
        """
        Fits StandardScaler and LogisticRegression strictly on X_train, y_train.
        Never touches validation or test data during fit.
        """
        # 1. Fit scaler on training data only
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)

        # 2. Fit Logistic Regression
        self.model = LogisticRegression(
            class_weight=self.class_weight,
            max_iter=self.max_iter,
            random_state=self.random_state,
            solver=self.solver,
            C=self.C
        )
        self.model.fit(X_train_scaled, y_train)
        self.is_fitted = True
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Transforms X using the pre-fitted scaler and returns predicted probabilities for class 1 (Attack).
        """
        if not self.is_fitted or self.model is None or self.scaler is None:
            raise RuntimeError("Model has not been fitted yet.")

        X_scaled = self.scaler.transform(X)
        probs = self.model.predict_proba(X_scaled)
        # Class 1 probability (handles edge cases where only 1 class is in training)
        if probs.shape[1] == 2:
            return probs[:, 1]
        elif probs.shape[1] == 1:
            # All training labels were single class
            class_label = self.model.classes_[0]
            return np.ones(len(X)) if class_label == 1 else np.zeros(len(X))
        return probs[:, 1]

    def predict(self, X: np.ndarray, threshold: Optional[float] = None) -> np.ndarray:
        """Predicts binary class based on probability and threshold."""
        th = threshold if threshold is not None else self.threshold
        probs = self.predict_proba(X)
        return (probs >= th).astype(int)

    def get_coefficients(self, feature_names: list) -> Dict[str, float]:
        """Returns feature coefficients sorted by absolute magnitude."""
        if not self.is_fitted or self.model is None:
            return {}
        coefs = self.model.coef_[0]
        return {feat: float(coef) for feat, coef in zip(feature_names, coefs)}

    def save(self, model_dir: str, prefix: str):
        """Saves model and scaler to the specified directory."""
        os.makedirs(model_dir, exist_ok=True)
        model_path = os.path.join(model_dir, f"{prefix}_model.joblib")
        scaler_path = os.path.join(model_dir, f"{prefix}_scaler.joblib")

        joblib.dump(self.model, model_path)
        joblib.dump(self.scaler, scaler_path)
        return model_path, scaler_path

    @classmethod
    def load(cls, model_path: str, scaler_path: str, threshold: float = 0.50):
        """Loads fitted model and scaler from joblib files."""
        instance = cls(threshold=threshold)
        instance.model = joblib.load(model_path)
        instance.scaler = joblib.load(scaler_path)
        instance.is_fitted = True
        return instance
