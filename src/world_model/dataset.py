"""
Dataset and DataLoader module for Phase 14 LSTM World Model.
Extracts 3D historical tensors (batch_size, 10, 22) and multi-task future targets
(future_state, future_attack, future_stage) for K in [1, 3, 6].
Enforces StandardScaler fitted strictly on TRAIN split only.
"""

import os
import torch
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any, Optional
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import StandardScaler

# Canonical Stage Vocabulary from Phase 12
STAGE_VOCABULARY = [
    "BENIGN",
    "RECONNAISSANCE",
    "INITIAL_ACCESS",
    "EXECUTION",
    "DISCOVERY",
    "CREDENTIAL_ACCESS",
    "LATERAL_MOVEMENT",
    "COMMAND_AND_CONTROL",
    "EXFILTRATION"
]
STAGE_TO_IDX = {s: i for i, s in enumerate(STAGE_VOCABULARY)}
IDX_TO_STAGE = {i: s for i, s in enumerate(STAGE_VOCABULARY)}

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

class TemporalSequenceDataset(Dataset):
    """PyTorch Dataset yielding 3D input tensor X (10, 22) and aligned multi-task targets."""
    def __init__(
        self,
        X_hist: np.ndarray,      # Shape: (N, 10, 22)
        y_state: Dict[int, np.ndarray],  # Horizon k -> Shape: (N, 22)
        y_attack: Dict[int, np.ndarray], # Horizon k -> Shape: (N,)
        y_stage: Dict[int, np.ndarray]   # Horizon k -> Shape: (N,)
    ):
        self.X_hist = torch.tensor(X_hist, dtype=torch.float32)
        self.y_state = {k: torch.tensor(v, dtype=torch.float32) for k, v in y_state.items()}
        self.y_attack = {k: torch.tensor(v, dtype=torch.float32) for k, v in y_attack.items()}
        self.y_stage = {k: torch.tensor(v, dtype=torch.long) for k, v in y_stage.items()}
        self.num_samples = len(X_hist)

    def __len__(self) -> int:
        return self.num_samples

    def __getitem__(self, idx: int) -> Dict[str, Any]:
        return {
            "x": self.X_hist[idx],
            "state": {k: self.y_state[k][idx] for k in self.y_state},
            "attack": {k: self.y_attack[k][idx] for k in self.y_attack},
            "stage": {k: self.y_stage[k][idx] for k in self.y_stage}
        }


def extract_temporal_arrays(
    df: pd.DataFrame,
    scaler: Optional[StandardScaler] = None,
    fit_scaler: bool = False,
    horizons: List[int] = [1, 3, 6]
) -> Tuple[np.ndarray, Dict[int, np.ndarray], Dict[int, np.ndarray], Dict[int, np.ndarray], StandardScaler]:
    """
    Constructs 3D array (N, 10, 22) for input sequence and 2D arrays for future targets.
    Fits or applies StandardScaler across the 22 state features.
    """
    N = len(df)
    L = 10
    num_feats = len(STATE_FEATURE_NAMES)

    # 1. Build unscaled 3D historical array: (N, 10, 22)
    # History step names in sequence_builder.py: S_t-9_..., S_t-8_..., ..., S_t_...
    X_raw = np.zeros((N, L, num_feats), dtype=np.float64)
    for step_idx, step_rel in enumerate(range(-9, 1)):
        prefix = f"S_t{step_rel:+d}_" if step_rel != 0 else "S_t_"
        step_cols = [f"{prefix}{feat}" for feat in STATE_FEATURE_NAMES]
        X_raw[:, step_idx, :] = df[step_cols].values

    # 2. Fit or apply StandardScaler
    # Reshape to (N * 10, 22) for scaler fitting / transforming across all temporal steps
    X_flat = X_raw.reshape(-1, num_feats)
    if fit_scaler:
        scaler = StandardScaler()
        X_scaled_flat = scaler.fit_transform(X_flat)
    else:
        if scaler is None:
            raise ValueError("Scaler must be provided when fit_scaler=False.")
        X_scaled_flat = scaler.transform(X_flat)

    X_hist = X_scaled_flat.reshape(N, L, num_feats)

    # 3. Future State targets (scaled using the exact same scaler for state regression)
    y_state = {}
    for k in horizons:
        target_cols = [f"target_S_k{k}_{feat}" for feat in STATE_FEATURE_NAMES]
        raw_target_state = df[target_cols].values.astype(np.float64)
        scaled_target_state = scaler.transform(raw_target_state)
        y_state[k] = scaled_target_state

    # 4. Future Attack targets (binary 0 or 1)
    y_attack = {}
    for k in horizons:
        y_attack[k] = df[f"future_attack_k{k}"].values.astype(np.float32)

    # 5. Future Stage targets (mapped to integer indices in [0, 8])
    y_stage = {}
    for k in horizons:
        stages_str = df[f"future_stage_k{k}"].astype(str).str.strip()
        stage_indices = stages_str.map(lambda s: STAGE_TO_IDX.get(s, 0)).values.astype(np.int64)
        y_stage[k] = stage_indices

    return X_hist, y_state, y_attack, y_stage, scaler


def prepare_dataloaders(
    df: pd.DataFrame,
    batch_size: int = 128,
    horizons: List[int] = [1, 3, 6]
) -> Tuple[DataLoader, DataLoader, DataLoader, StandardScaler, Dict[str, Any]]:
    """
    Splits DataFrame by chronological split ('TRAIN', 'VAL', 'TEST').
    Fits StandardScaler strictly on TRAIN.
    Returns PyTorch DataLoaders and metadata.
    """
    train_df = df[df["split"] == "TRAIN"].reset_index(drop=True)
    val_df = df[df["split"] == "VAL"].reset_index(drop=True)
    test_df = df[df["split"] == "TEST"].reset_index(drop=True)

    # Fit scaler strictly on train
    X_train, y_s_tr, y_a_tr, y_st_tr, scaler = extract_temporal_arrays(
        train_df, fit_scaler=True, horizons=horizons
    )
    X_val, y_s_va, y_a_va, y_st_val, _ = extract_temporal_arrays(
        val_df, scaler=scaler, fit_scaler=False, horizons=horizons
    )
    X_test, y_s_te, y_a_te, y_st_te, _ = extract_temporal_arrays(
        test_df, scaler=scaler, fit_scaler=False, horizons=horizons
    )

    train_ds = TemporalSequenceDataset(X_train, y_s_tr, y_a_tr, y_st_tr)
    val_ds = TemporalSequenceDataset(X_val, y_s_va, y_a_va, y_st_val)
    test_ds = TemporalSequenceDataset(X_test, y_s_te, y_a_te, y_st_te)

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True, drop_last=False)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False, drop_last=False)
    test_loader = DataLoader(test_ds, batch_size=batch_size, shuffle=False, drop_last=False)

    # Compute positive class weighting for BCEWithLogitsLoss from TRAIN split only
    pos_weights = {}
    for k in horizons:
        num_pos = float(np.sum(y_a_tr[k] == 1))
        num_neg = float(np.sum(y_a_tr[k] == 0))
        # Weight = neg / pos (standard pos_weight in PyTorch)
        pos_weight = (num_neg / max(num_pos, 1.0))
        pos_weights[k] = float(pos_weight)

    meta = {
        "train_samples": len(train_df),
        "val_samples": len(val_df),
        "test_samples": len(test_df),
        "feature_count": len(STATE_FEATURE_NAMES),
        "history_length": 10,
        "horizons": horizons,
        "pos_weights": pos_weights,
        "stage_vocabulary": STAGE_VOCABULARY
    }

    return train_loader, val_loader, test_loader, scaler, meta
