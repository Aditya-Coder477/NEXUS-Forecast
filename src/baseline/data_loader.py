"""
Data loader and anti-leakage audit module for Phase 13 Baseline.
Loads validated Phase 12 forecast sequences, extracts the current state S_t features,
and enforces rigorous anti-leakage checks.
"""

import os
import glob
import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Any, Optional

# The exact 22 canonical state features defined in Phase 12 state_schema.yaml
STATE_FEATURE_NAMES = [
    "total_flows",
    "unique_src_hosts",
    "unique_dst_hosts",
    "unique_dst_ports",
    "unique_protocols",
    "total_packets",
    "total_bytes",
    "inbound_bytes",
    "outbound_bytes",
    "inbound_outbound_ratio",
    "mean_flow_duration",
    "mean_packet_rate",
    "mean_byte_rate",
    "mean_iat",
    "std_iat",
    "syn_count",
    "ack_count",
    "rst_count",
    "fin_count",
    "connection_failure_rate",
    "unique_host_pair_count",
    "fan_out_ratio"
]

class BaselineDataLoader:
    def __init__(self, sequence_dir: str = "data/processed/forecast_sequences"):
        self.sequence_dir = sequence_dir
        self.feature_names = [f"S_t_{feat}" for feat in STATE_FEATURE_NAMES]

    def get_feature_names(self) -> List[str]:
        """Returns the list of 22 S_t feature columns used as model input."""
        return list(self.feature_names)

    def load_dataset(self, file_name: str) -> pd.DataFrame:
        """Loads a single forecast sequence parquet file and audits its structure."""
        file_path = os.path.join(self.sequence_dir, file_name)
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Sequence artifact not found at {file_path}")

        df = pd.read_parquet(file_path)
        self.verify_dataset_integrity(df, file_name)
        return df

    def verify_dataset_integrity(self, df: pd.DataFrame, dataset_label: str):
        """Performs strict data integrity and anti-leakage checks."""
        # 1. Check all 22 S_t features are present
        missing_features = [f for f in self.feature_names if f not in df.columns]
        assert not missing_features, f"[{dataset_label}] Missing S_t features: {missing_features}"

        # 2. Check targets are present
        for k in [1, 3, 6]:
            target_col = f"future_attack_k{k}"
            assert target_col in df.columns, f"[{dataset_label}] Missing target column {target_col}"

        # 3. Check split column is present and contains only TRAIN, VAL, TEST
        assert "split" in df.columns, f"[{dataset_label}] Missing 'split' column"
        splits = set(df["split"].unique())
        expected_splits = {"TRAIN", "VAL", "TEST"}
        assert splits.issubset(expected_splits), f"[{dataset_label}] Unexpected splits: {splits}"

        # 4. Check for null or inf values in S_t features
        null_count = df[self.feature_names].isna().sum().sum()
        assert null_count == 0, f"[{dataset_label}] Found {null_count} nulls in S_t features!"

        inf_count = np.isinf(df[self.feature_names].values).sum()
        assert inf_count == 0, f"[{dataset_label}] Found {inf_count} infinite values in S_t features!"

        # 5. Check duplicate sequence_id
        if "sequence_id" in df.columns:
            dup_ids = df["sequence_id"].duplicated().sum()
            assert dup_ids == 0, f"[{dataset_label}] Found {dup_ids} duplicate sequence_ids!"

        # 6. Check sequence_id overlap across splits
        train_ids = set(df[df["split"] == "TRAIN"]["sequence_id"])
        val_ids = set(df[df["split"] == "VAL"]["sequence_id"])
        test_ids = set(df[df["split"] == "TEST"]["sequence_id"])
        assert len(train_ids.intersection(val_ids)) == 0, f"[{dataset_label}] Leakage: Train/Val ID overlap!"
        assert len(train_ids.intersection(test_ids)) == 0, f"[{dataset_label}] Leakage: Train/Test ID overlap!"
        assert len(val_ids.intersection(test_ids)) == 0, f"[{dataset_label}] Leakage: Val/Test ID overlap!"

    def get_split_data(
        self, df: pd.DataFrame, horizon: int
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, Dict[str, Any]]:
        """
        Extracts X (current state S_t) and y (future_attack_k{horizon}) for TRAIN, VAL, TEST.
        Returns:
            X_train, y_train, X_val, y_val, X_test, y_test, metadata
        """
        target_col = f"future_attack_k{horizon}"
        if target_col not in df.columns:
            raise ValueError(f"Target column {target_col} not found in DataFrame.")

        train_mask = df["split"] == "TRAIN"
        val_mask = df["split"] == "VAL"
        test_mask = df["split"] == "TEST"

        X_train = df.loc[train_mask, self.feature_names].values.astype(np.float64)
        y_train = df.loc[train_mask, target_col].values.astype(np.int64)

        X_val = df.loc[val_mask, self.feature_names].values.astype(np.float64)
        y_val = df.loc[val_mask, target_col].values.astype(np.int64)

        X_test = df.loc[test_mask, self.feature_names].values.astype(np.float64)
        y_test = df.loc[test_mask, target_col].values.astype(np.int64)

        # Class distribution audit
        def dist_info(arr):
            b_cnt = int(np.sum(arr == 0))
            a_cnt = int(np.sum(arr == 1))
            tot = len(arr)
            pct = (a_cnt / tot * 100.0) if tot > 0 else 0.0
            return {"benign_count": b_cnt, "attack_count": a_cnt, "total": tot, "attack_pct": round(pct, 2)}

        # Time range audit
        def time_range(mask):
            sub = df.loc[mask]
            if "prediction_origin" in sub.columns and not sub.empty:
                return [str(sub["prediction_origin"].min()), str(sub["prediction_origin"].max())]
            return ["N/A", "N/A"]

        metadata = {
            "horizon": horizon,
            "feature_count": len(self.feature_names),
            "features": list(self.feature_names),
            "distribution": {
                "train": dist_info(y_train),
                "val": dist_info(y_val),
                "test": dist_info(y_test)
            },
            "time_range": {
                "train": time_range(train_mask),
                "val": time_range(val_mask),
                "test": time_range(test_mask)
            }
        }

        return X_train, y_train, X_val, y_val, X_test, y_test, metadata
