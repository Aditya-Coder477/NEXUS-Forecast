"""
Forecast Sequence Builder and Chronological Splitting Module for NEXUS-Forecast.

Converts windowed network state vectors S_t into multi-step forecasting sequences
with history length L (default L=10) and prediction horizons K in [1, 3, 6].
Constructs future state targets, future attack indicators, future stage classifications,
and time_to_next_attack_seconds targets.
Enforces strict chronological train/validation/test partitioning without temporal leakage.
"""

import pandas as pd
import numpy as np
from typing import List, Dict, Any, Tuple, Optional

class SequenceBuilder:
    def __init__(self, history_windows: int = 10, forecast_horizons: Optional[List[int]] = None,
                 train_ratio: float = 0.70, val_ratio: float = 0.15, test_ratio: float = 0.15):
        self.history_windows = history_windows
        self.forecast_horizons = sorted(forecast_horizons or [1, 3, 6])
        self.train_ratio = train_ratio
        self.val_ratio = val_ratio
        self.test_ratio = test_ratio

        # Feature columns comprising S_t (22 dimensions)
        self.state_features = [
            "total_flows", "unique_src_hosts", "unique_dst_hosts", "unique_dst_ports",
            "unique_protocols", "total_packets", "total_bytes", "inbound_bytes",
            "outbound_bytes", "inbound_outbound_ratio", "mean_flow_duration",
            "mean_packet_rate", "mean_byte_rate", "mean_iat", "std_iat",
            "syn_count", "ack_count", "rst_count", "fin_count",
            "connection_failure_rate", "unique_host_pair_count", "fan_out_ratio"
        ]

    def build_sequences_for_scenario(self, windows_df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """
        Builds chronological sequences from a scenario's windows DataFrame.
        """
        target_offsets = {k: k + 1 for k in self.forecast_horizons}
        max_target_offset = max(target_offsets.values())
        min_required = self.history_windows + max_target_offset

        if windows_df.empty or len(windows_df) < min_required:
            return pd.DataFrame(), {
                "generated": 0,
                "discarded": len(windows_df),
                "reason": f"Insufficient windows ({len(windows_df)} < {min_required}) for history length + max horizon"
            }

        # Ensure sorted
        windows_df = windows_df.sort_values("window_start").reset_index(drop=True)
        N = len(windows_df)
        max_k = max(self.forecast_horizons)
        L = self.history_windows

        records = []
        w_starts = pd.to_datetime(windows_df["window_start"])
        w_ends = pd.to_datetime(windows_df["window_end"])
        attack_flags = windows_df["window_attack_flag"].values
        attack_stages = windows_df["primary_attack_stage"].values

        dataset_name = windows_df["dataset"].iloc[0]
        scenario_id = windows_df["scenario_id"].iloc[0]

        # With window_size=60s and step_size=30s:
        # Window i ends at t_0 + 30*i + 60s (prediction_origin).
        # Window i+1 starts at t_0 + 30*(i+1) = t_0 + 30*i + 30s (which is < prediction_origin, sharing 30s of flows).
        # Window i+2 starts at t_0 + 30*(i+2) = t_0 + 30*i + 60s = prediction_origin!
        # Therefore, the immediate non-overlapping future window is at index i + 2.
        # More generally, for nominal forecast horizon k in [1, 3, 6]:
        # target_window_index = i + k + 1 (i.e. i+2 for k=1 (+30s nominal), i+4 for k=3 (+90s nominal), i+7 for k=6 (+180s nominal)).
        # This guarantees: max(input_timestamp) <= prediction_origin <= min(target_timestamp) with 0 shared flows!
        
        target_offsets = {k: k + 1 for k in self.forecast_horizons}
        max_target_offset = max(target_offsets.values())

        # Valid prediction origins run from index i = L - 1 to N - max_target_offset - 1
        valid_indices = list(range(L - 1, N - max_target_offset))

        for idx, i in enumerate(valid_indices):
            # Input window slice: [i - L + 1, i]
            input_slice = windows_df.iloc[i - L + 1 : i + 1]
            pred_origin = w_ends.iloc[i]
            hist_start = w_starts.iloc[i - L + 1]

            # Structural anti-leakage verification:
            # The earliest future target window must begin at or after the prediction origin (input end)
            earliest_target_idx = i + target_offsets[min(self.forecast_horizons)]
            earliest_target_start = w_starts.iloc[earliest_target_idx]
            assert pred_origin <= earliest_target_start, (
                f"Temporal leakage detected at sequence index {idx}: "
                f"prediction_origin ({pred_origin}) > earliest_target_start ({earliest_target_start})"
            )

            # Sequence item
            seq_dict = {
                "sequence_id": f"{dataset_name}_{scenario_id}_seq_{idx:05d}",
                "dataset": dataset_name,
                "scenario_id": scenario_id,
                "history_start": hist_start.isoformat(),
                "prediction_origin": pred_origin.isoformat(),
                "current_attack_flag": int(attack_flags[i]),
                "current_stage": str(attack_stages[i])
            }

            # Flatten history state features: X_t (L * 22 features)
            # S_0 is earliest (t - L + 1), S_{L-1} is current state S_t
            for step_back in range(L):
                window_row = input_slice.iloc[step_back]
                step_rel = step_back - (L - 1)  # e.g. -9, -8, ..., 0
                prefix = f"S_t{step_rel:+d}_" if step_rel != 0 else "S_t_"
                for feat in self.state_features:
                    seq_dict[f"{prefix}{feat}"] = float(window_row[feat])

            # Future targets for each horizon K
            for k in self.forecast_horizons:
                tgt_idx = i + target_offsets[k]
                target_row = windows_df.iloc[tgt_idx]
                target_flag = int(attack_flags[tgt_idx])
                target_stage = str(attack_stages[tgt_idx])

                seq_dict[f"future_attack_k{k}"] = target_flag
                # Rule 9: If horizon is benign, retain BENIGN
                seq_dict[f"future_stage_k{k}"] = target_stage if target_flag == 1 else "BENIGN"
                seq_dict[f"target_time_k{k}"] = w_starts.iloc[tgt_idx].isoformat()

                # Also save target state features for multi-step world model prediction
                for feat in self.state_features:
                    seq_dict[f"target_S_k{k}_{feat}"] = float(target_row[feat])

            # time_to_next_attack_seconds (Rule 11)
            # Search future non-overlapping windows within max_target_offset
            ttna = -1.0
            for step_ahead in range(target_offsets[min(self.forecast_horizons)], max_target_offset + 1):
                if attack_flags[i + step_ahead] == 1:
                    future_start = w_starts.iloc[i + step_ahead]
                    diff_sec = (future_start - pred_origin).total_seconds()
                    ttna = max(0.0, float(diff_sec))
                    break
            seq_dict["time_to_next_attack_seconds"] = ttna

            records.append(seq_dict)

        seq_df = pd.DataFrame(records)
        if seq_df.empty:
            return pd.DataFrame(), {"generated": 0, "discarded": len(windows_df), "reason": "No valid sequences generated"}

        # Chronological Train / Val / Test Split
        total_seqs = len(seq_df)
        n_train = int(total_seqs * self.train_ratio)
        n_val = int(total_seqs * self.val_ratio)
        # Remaining goes to test
        n_test = total_seqs - n_train - n_val

        splits = ["TRAIN"] * n_train + ["VAL"] * n_val + ["TEST"] * n_test
        seq_df["split"] = splits

        stats = {
            "generated": total_seqs,
            "discarded": len(windows_df) - total_seqs,
            "train_count": n_train,
            "val_count": n_val,
            "test_count": n_test
        }

        return seq_df, stats
