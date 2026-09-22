"""
Strict Input Validation Component for NEXUS-Forecast Phase 19.
Validates sequence tensors, flat tabular sequences, and raw flow records.
"""

import numpy as np
import pandas as pd
from typing import Tuple, Union, List, Dict, Any

from src.world_model.dataset import STATE_FEATURE_NAMES


class ValidationError(ValueError):
    """Raised when inference input data fails schema or numerical integrity checks."""
    pass


class InputValidator:
    """
    Validates input schemas, dimensions, and finite numerical constraints.
    """

    @classmethod
    def validate_sequence_array(cls, arr: Union[np.ndarray, Any]) -> np.ndarray:
        """
        Validate and format a numpy array or tensor into shape (N, 10, 22).
        """
        if not isinstance(arr, np.ndarray):
            try:
                arr = np.array(arr, dtype=np.float32)
            except Exception as e:
                raise ValidationError(f"Could not convert input to float numpy array: {e}")

        if arr.ndim == 2:
            if arr.shape == (10, 22):
                arr = np.expand_dims(arr, axis=0)
            else:
                raise ValidationError(f"Expected 2D input of shape (10, 22), but got {arr.shape}")
        elif arr.ndim == 3:
            if arr.shape[1] != 10 or arr.shape[2] != 22:
                raise ValidationError(f"Expected 3D input of shape (N, 10, 22), but got {arr.shape}")
        else:
            raise ValidationError(f"Expected 2D or 3D input array, but got array with {arr.ndim} dimensions.")

        if not np.isfinite(arr).all():
            nan_count = np.isnan(arr).sum()
            inf_count = np.isinf(arr).sum()
            raise ValidationError(
                f"Input array contains non-finite numerical values (NaN: {nan_count}, Inf: {inf_count})."
            )

        return arr.astype(np.float32)

    @classmethod
    def extract_sequences_from_dataframe(cls, df: pd.DataFrame) -> np.ndarray:
        """
        Extract (N, 10, 22) sequence array from flat sequence dataframe.
        Checks for prefix columns: S_t-9_... through S_t_...
        """
        num_feats = len(STATE_FEATURE_NAMES)
        L = 10
        N = len(df)

        if N == 0:
            raise ValidationError("Input DataFrame contains zero rows.")

        # Check if flat sequence columns exist
        sample_col = f"S_t-9_{STATE_FEATURE_NAMES[0]}"
        if sample_col in df.columns:
            arr = np.zeros((N, L, num_feats), dtype=np.float32)
            for step_idx, step_rel in enumerate(range(-9, 1)):
                prefix = f"S_t{step_rel:+d}_" if step_rel != 0 else "S_t_"
                step_cols = [f"{prefix}{feat}" for feat in STATE_FEATURE_NAMES]
                missing = [c for c in step_cols if c not in df.columns]
                if missing:
                    raise ValidationError(f"DataFrame missing required temporal state columns: {missing[:5]}")
                arr[:, step_idx, :] = df[step_cols].values.astype(np.float32)

            return cls.validate_sequence_array(arr)

        # Alternative: 22 feature columns repeated or single window
        missing_feats = [f for f in STATE_FEATURE_NAMES if f not in df.columns]
        if not missing_feats and len(df) >= 10:
            # Assume rows represent consecutive temporal windows
            windows = []
            for i in range(len(df) - 10 + 1):
                sub = df.iloc[i : i + 10][STATE_FEATURE_NAMES].values.astype(np.float32)
                windows.append(sub)
            return cls.validate_sequence_array(np.array(windows, dtype=np.float32))

        raise ValidationError(
            f"DataFrame columns do not match expected sequence schema (neither S_t-9_* prefixes nor 22 feature names)."
        )
