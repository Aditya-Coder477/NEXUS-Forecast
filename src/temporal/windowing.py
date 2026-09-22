"""
Temporal Window Builder and Compact Network State Generator for NEXUS-Forecast.

Aggregates canonical flows into chronological rolling windows (W_t = [t, t + delta_t)).
Computes the 22-dimensional state vector S_t and deterministic window-level ground truth.
Enforces strict anti-leakage guarantees (no future information in S_t).
"""

import pandas as pd
import numpy as np
from typing import List, Dict, Any, Optional

# Priority hierarchy for deterministic multi-stage tie-breaking:
# EXFILTRATION > COMMAND_AND_CONTROL > LATERAL_MOVEMENT > CREDENTIAL_ACCESS >
# DISCOVERY > EXECUTION > INITIAL_ACCESS > RECONNAISSANCE > BENIGN
STAGE_PRIORITY = {
    "EXFILTRATION": 9,
    "COMMAND_AND_CONTROL": 8,
    "LATERAL_MOVEMENT": 7,
    "CREDENTIAL_ACCESS": 6,
    "DISCOVERY": 5,
    "EXECUTION": 4,
    "INITIAL_ACCESS": 3,
    "RECONNAISSANCE": 2,
    "BENIGN": 1
}

# Mapping from common dataset attack labels to macroscopic NEXUS stages:
ATTACK_TYPE_TO_STAGE = {
    "BENIGN": "BENIGN",
    "NORMAL": "BENIGN",
    "BACKGROUND": "BENIGN",
    # DoS / DDoS -> EXECUTION / IMPACT / C2
    "DDOS": "COMMAND_AND_CONTROL",
    "DOS": "EXECUTION",
    "DOS HULK": "EXECUTION",
    "DOS GOLDENEYE": "EXECUTION",
    "DOS SLOWLORIS": "EXECUTION",
    "DOS SLOWHTTPTEST": "EXECUTION",
    "HEARTBLEED": "INITIAL_ACCESS",
    # Scanning / Recon
    "PORTSCAN": "RECONNAISSANCE",
    "RECONNAISSANCE": "RECONNAISSANCE",
    "FUZZERS": "RECONNAISSANCE",
    "ANALYSIS": "RECONNAISSANCE",
    # Brute Force -> CREDENTIAL_ACCESS
    "FTP-PATATOR": "CREDENTIAL_ACCESS",
    "SSH-PATATOR": "CREDENTIAL_ACCESS",
    # Web attacks -> INITIAL_ACCESS
    "WEB ATTACK  BRUTE FORCE": "CREDENTIAL_ACCESS",
    "WEB ATTACK  XSS": "INITIAL_ACCESS",
    "WEB ATTACK  SQL INJECTION": "INITIAL_ACCESS",
    "EXPLOITS": "INITIAL_ACCESS",
    "GENERIC": "EXECUTION",
    "SHELLCODE": "EXECUTION",
    "WORMS": "LATERAL_MOVEMENT",
    "BACKDOOR": "COMMAND_AND_CONTROL",
    # Botnet -> COMMAND_AND_CONTROL
    "BOT": "COMMAND_AND_CONTROL",
}

def map_attack_type_to_stage(attack_type: str) -> str:
    cleaned = attack_type.strip().upper()
    if cleaned in ATTACK_TYPE_TO_STAGE:
        return ATTACK_TYPE_TO_STAGE[cleaned]
    if "BOTNET" in cleaned or "BOT" in cleaned:
        return "COMMAND_AND_CONTROL"
    if "SCAN" in cleaned:
        return "RECONNAISSANCE"
    if "PATATOR" in cleaned or "BRUTE" in cleaned:
        return "CREDENTIAL_ACCESS"
    if "INFILTRATION" in cleaned or "INFILTERATION" in cleaned:
        return "INITIAL_ACCESS"
    return "INITIAL_ACCESS"


class TemporalWindowBuilder:
    def __init__(self, window_size_seconds: int = 60, step_size_seconds: int = 30, min_flows: int = 1):
        self.window_size_seconds = window_size_seconds
        self.step_size_seconds = step_size_seconds
        self.min_flows = min_flows

    def build_windows_from_dataframe(self, df: pd.DataFrame, dataset_name: str, scenario_id: str) -> pd.DataFrame:
        """
        Converts chronological canonical flows into compact 22-dimensional network state vectors S_t.
        """
        if df.empty:
            return pd.DataFrame()

        # Ensure sorted by normalized timestamp
        df = df.sort_values("timestamp_normalized").reset_index(drop=True)

        t_min = df["timestamp_normalized"].min()
        t_max = df["timestamp_normalized"].max()

        window_delta = pd.Timedelta(seconds=self.window_size_seconds)
        step_delta = pd.Timedelta(seconds=self.step_size_seconds)

        # Vectorized searchsorted for fast window intervals
        ts_values = df["timestamp_normalized"].values
        total_records = len(ts_values)

        windows = []
        cur_start = t_min

        while cur_start < t_max:
            cur_end = cur_start + window_delta
            
            # Binary search indices for [cur_start, cur_end)
            i_start = np.searchsorted(ts_values, cur_start.to_numpy(), side="left")
            i_end = np.searchsorted(ts_values, cur_end.to_numpy(), side="left")

            flow_count = i_end - i_start
            if flow_count >= self.min_flows:
                w_df = df.iloc[i_start:i_end]

                # Compute compact 22-dimensional state features
                src_ips = w_df["src_ip"].values
                dst_ips = w_df["dst_ip"].values
                src_ports = w_df["src_port"].values
                dst_ports = w_df["dst_port"].values
                protocols = w_df["protocol"].values
                durations = w_df["duration"].values
                fwd_pkts = w_df["packets_forward"].values
                bwd_pkts = w_df["packets_backward"].values
                fwd_bytes = w_df["bytes_forward"].values
                bwd_bytes = w_df["bytes_backward"].values
                pkt_rates = w_df["packet_rate"].values
                byte_rates = w_df["byte_rate"].values
                inbounds = w_df["is_inbound"].values
                outbounds = w_df["is_outbound"].values

                tot_pkts = fwd_pkts + bwd_pkts
                tot_bytes = fwd_bytes + bwd_bytes

                unique_src = len(np.unique(src_ips))
                unique_dst = len(np.unique(dst_ips))
                unique_dports = len(np.unique(dst_ports))
                unique_protos = len(np.unique(protocols))

                # Graph host pairs
                host_pairs = set(zip(src_ips, dst_ips))
                unique_pairs = len(host_pairs)
                fan_out = float(unique_dst) / float(unique_src + 1e-4)

                in_bytes = int(np.sum(tot_bytes[inbounds])) if np.any(inbounds) else 0
                out_bytes = int(np.sum(tot_bytes[outbounds])) if np.any(outbounds) else 0
                in_out_ratio = float(in_bytes + 1) / float(out_bytes + 1)

                mean_dur = float(np.mean(durations))
                mean_prate = float(np.mean(pkt_rates))
                mean_brate = float(np.mean(byte_rates))

                # IAT handling: only if available (not -1)
                iats = w_df["iat_mean"].values
                valid_iats = iats[iats >= 0]
                mean_iat = float(np.mean(valid_iats)) if len(valid_iats) > 0 else -1.0
                std_iats = w_df["iat_std"].values
                valid_stds = std_iats[std_iats >= 0]
                mean_std_iat = float(np.mean(valid_stds)) if len(valid_stds) > 0 else -1.0

                syn_c = int(np.sum(w_df["tcp_syn"].values))
                ack_c = int(np.sum(w_df["tcp_ack"].values))
                rst_c = int(np.sum(w_df["tcp_rst"].values))
                fin_c = int(np.sum(w_df["tcp_fin"].values))
                conn_fail_rate = float(rst_c + 1) / float(syn_c + 1)

                # Ground Truth Aggregations
                labels = w_df["label"].values
                attack_count = int(np.sum(labels == 1))
                attack_flag = 1 if attack_count > 0 else 0
                attack_ratio = float(attack_count) / float(flow_count)

                if attack_flag == 0:
                    primary_type = "BENIGN"
                    primary_stage = "BENIGN"
                else:
                    # Attack types present
                    attack_flows = w_df[w_df["label"] == 1]
                    type_counts = attack_flows["attack_type"].value_counts()
                    # Tie-breaking rule: highest flow count, lexical tie-break
                    max_cnt = type_counts.iloc[0]
                    candidates = type_counts[type_counts == max_cnt].index.tolist()
                    candidates.sort()
                    primary_type = candidates[0]

                    # Stage assignment: map all present attack types to stages, select highest priority
                    present_stages = [map_attack_type_to_stage(t) for t in type_counts.index]
                    # Sort by STAGE_PRIORITY descending
                    present_stages.sort(key=lambda s: STAGE_PRIORITY.get(s, 0), reverse=True)
                    primary_stage = present_stages[0]

                windows.append({
                    "window_id": f"{dataset_name}_{scenario_id}_win_{len(windows):06d}",
                    "dataset": dataset_name,
                    "scenario_id": scenario_id,
                    "window_start": cur_start.isoformat(),
                    "window_end": cur_end.isoformat(),
                    "total_flows": flow_count,
                    "unique_src_hosts": unique_src,
                    "unique_dst_hosts": unique_dst,
                    "unique_dst_ports": unique_dports,
                    "unique_protocols": unique_protos,
                    "total_packets": int(np.sum(tot_pkts)),
                    "total_bytes": int(np.sum(tot_bytes)),
                    "inbound_bytes": in_bytes,
                    "outbound_bytes": out_bytes,
                    "inbound_outbound_ratio": in_out_ratio,
                    "mean_flow_duration": mean_dur,
                    "mean_packet_rate": mean_prate,
                    "mean_byte_rate": mean_brate,
                    "mean_iat": mean_iat,
                    "std_iat": mean_std_iat,
                    "syn_count": syn_c,
                    "ack_count": ack_c,
                    "rst_count": rst_c,
                    "fin_count": fin_c,
                    "connection_failure_rate": conn_fail_rate,
                    "unique_host_pair_count": unique_pairs,
                    "fan_out_ratio": fan_out,
                    # Ground Truth Labels
                    "window_attack_flag": attack_flag,
                    "window_attack_ratio": attack_ratio,
                    "primary_attack_type": primary_type,
                    "primary_attack_stage": primary_stage
                })

            cur_start += step_delta

        return pd.DataFrame(windows)
