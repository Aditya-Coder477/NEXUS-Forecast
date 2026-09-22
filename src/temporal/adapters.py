"""
Dataset-Specific Adapters and Canonical Schema Parser for NEXUS-Forecast.

Implements:
- CICIDS2017Adapter
- UNSWNB15Adapter
- CTU13Adapter
- CanonicalFlowRecord

Ensures:
- Explicit feature derivation and availability tracking (no fabricated packet-level metrics for CTU-13).
- Strict timestamp normalization with preservation of timestamp_raw and scenario_id.
- Network boundary checks for inbound/outbound traffic orientation.
- Safe chunked streaming to prevent memory exhaustion on Windows host.
"""

import os
import ipaddress
import pandas as pd
import numpy as np
from typing import Generator, Dict, Any, List, Optional

class CanonicalFlowRecord:
    """Canonical representation of a single network flow record."""
    __slots__ = (
        'dataset', 'scenario_id', 'timestamp_raw', 'timestamp_normalized',
        'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'duration',
        'packets_forward', 'packets_backward', 'bytes_forward', 'bytes_backward',
        'packet_rate', 'byte_rate', 'iat_mean', 'iat_std', 'iat_max',
        'tcp_syn', 'tcp_ack', 'tcp_fin', 'tcp_rst', 'ttl_mean', 'ttl_std',
        'payload_size_mean', 'payload_size_std', 'label', 'attack_type',
        'derived_approximation', 'is_inbound', 'is_outbound'
    )

    def __init__(self, **kwargs):
        for slot in self.__slots__:
            setattr(self, slot, kwargs.get(slot, None))


class NetworkBoundaryChecker:
    """Checks whether an IP address belongs to monitored/internal subnets."""
    def __init__(self, cidrs: List[str]):
        self.networks = []
        for c in cidrs:
            try:
                self.networks.append(ipaddress.ip_network(c.strip(), strict=False))
            except Exception:
                pass

    def contains(self, ip_str: str) -> bool:
        if not self.networks or not ip_str:
            return False
        try:
            addr = ipaddress.ip_address(ip_str.strip())
            return any(addr in net for net in self.networks)
        except Exception:
            return False


class CICIDS2017Adapter:
    """Adapter for Canadian Institute for Cybersecurity IDS2017 CSV flow records."""

    def __init__(self, monitored_subnets: Optional[List[str]] = None):
        subnets = monitored_subnets or ["192.168.10.0/24", "192.168.1.0/24", "172.16.0.0/16"]
        self.boundary = NetworkBoundaryChecker(subnets)

    def parse_file(self, file_path: str, chunksize: int = 100000) -> Generator[pd.DataFrame, None, None]:
        fname = os.path.basename(file_path)
        scenario_id = fname.replace(".pcap_ISCX.csv", "").replace(".csv", "")

        # Read first line to strip column names cleanly
        with open(file_path, "r", encoding="latin1") as f:
            raw_cols = [c.strip() for c in f.readline().split(",")]

        # Mapping dictionary from stripped column name to canonical
        col_map = {
            "Flow ID": "flow_id",
            "Source IP": "src_ip",
            "Destination IP": "dst_ip",
            "Source Port": "src_port",
            "Destination Port": "dst_port",
            "Protocol": "protocol",
            "Timestamp": "timestamp_raw",
            "Flow Duration": "duration_raw",
            "Total Fwd Packets": "packets_forward",
            "Total Backward Packets": "packets_backward",
            "Total Length of Fwd Packets": "bytes_forward",
            "Total Length of Bwd Packets": "bytes_backward",
            "Flow Packets/s": "packet_rate",
            "Flow Bytes/s": "byte_rate",
            "Flow IAT Mean": "iat_mean",
            "Flow IAT Std": "iat_std",
            "Flow IAT Max": "iat_max",
            "SYN Flag Count": "tcp_syn",
            "ACK Flag Count": "tcp_ack",
            "FIN Flag Count": "tcp_fin",
            "RST Flag Count": "tcp_rst",
            "Fwd Packet Length Mean": "payload_size_mean",
            "Fwd Packet Length Std": "payload_size_std",
            "Label": "label_raw"
        }

        for chunk in pd.read_csv(file_path, chunksize=chunksize, encoding="latin1", on_bad_lines="skip", low_memory=False):
            chunk.columns = [c.strip() for c in chunk.columns]
            # Select available intersection
            use_cols = {orig: target for orig, target in col_map.items() if orig in chunk.columns}
            sub = chunk[list(use_cols.keys())].rename(columns=use_cols).copy()

            # 1. Normalize Timestamp
            sub["timestamp_normalized"] = pd.to_datetime(sub["timestamp_raw"], format="mixed", errors="coerce")
            sub = sub[sub["timestamp_normalized"].notna()].copy()
            if sub.empty:
                continue

            # 2. Flow Duration: CICFlowMeter is in microseconds -> convert to seconds
            sub["duration"] = (sub["duration_raw"].astype(float) / 1e6).clip(lower=0.0)

            # 3. Numeric conversions & sanitization
            sub["packets_forward"] = pd.to_numeric(sub["packets_forward"], errors="coerce").fillna(0).astype(np.uint32)
            sub["packets_backward"] = pd.to_numeric(sub["packets_backward"], errors="coerce").fillna(0).astype(np.uint32)
            sub["bytes_forward"] = pd.to_numeric(sub["bytes_forward"], errors="coerce").fillna(0).astype(np.uint64)
            sub["bytes_backward"] = pd.to_numeric(sub["bytes_backward"], errors="coerce").fillna(0).astype(np.uint64)

            # 4. Safe Rate calculation
            dur_safe = np.maximum(sub["duration"].values, 1e-4)
            sub["packet_rate"] = (sub["packets_forward"] + sub["packets_backward"]) / dur_safe
            sub["byte_rate"] = (sub["bytes_forward"] + sub["bytes_backward"]) / dur_safe

            # 5. Unavailable fields in CICFlowMeter: ttl_mean, ttl_std
            sub["ttl_mean"] = -1.0
            sub["ttl_std"] = -1.0

            # 6. Flag counts (binary flags in CSV)
            for flag in ["tcp_syn", "tcp_ack", "tcp_fin", "tcp_rst"]:
                if flag in sub.columns:
                    sub[flag] = pd.to_numeric(sub[flag], errors="coerce").fillna(0).astype(np.uint8)
                else:
                    sub[flag] = 0

            # 7. Labels
            labels_str = sub["label_raw"].astype(str).str.strip()
            sub["attack_type"] = labels_str
            sub["label"] = (labels_str.str.upper() != "BENIGN").astype(np.uint8)

            # 8. Protocol string standardization
            proto_map = {6: "TCP", 17: "UDP", 1: "ICMP", "6": "TCP", "17": "UDP", "1": "ICMP"}
            sub["protocol"] = sub["protocol"].map(proto_map).fillna("OTHER").astype(str)

            # 9. Scenario & Dataset IDs
            sub["dataset"] = "CIC-IDS2017"
            sub["scenario_id"] = scenario_id
            sub["derived_approximation"] = False

            # 10. Directional boundary tagging
            sub["src_ip"] = sub["src_ip"].astype(str)
            sub["dst_ip"] = sub["dst_ip"].astype(str)
            src_in = sub["src_ip"].apply(self.boundary.contains).astype(bool)
            dst_in = sub["dst_ip"].apply(self.boundary.contains).astype(bool)
            sub["is_outbound"] = src_in & (~dst_in)
            sub["is_inbound"] = dst_in & (~src_in)

            # Ports as integer
            sub["src_port"] = pd.to_numeric(sub["src_port"], errors="coerce").fillna(0).astype(np.uint16)
            sub["dst_port"] = pd.to_numeric(sub["dst_port"], errors="coerce").fillna(0).astype(np.uint16)

            yield sub


class UNSWNB15Adapter:
    """Adapter for University of New South Wales NB15 CICFlowMeter CSV."""

    def __init__(self, monitored_subnets: Optional[List[str]] = None):
        subnets = monitored_subnets or ["175.45.176.0/24", "149.171.126.0/24"]
        self.boundary = NetworkBoundaryChecker(subnets)

    def parse_file(self, file_path: str, chunksize: int = 100000) -> Generator[pd.DataFrame, None, None]:
        fname = os.path.basename(file_path)
        scenario_id = "full_capture"

        col_map = {
            "Src IP": "src_ip",
            "Dst IP": "dst_ip",
            "Src Port": "src_port",
            "Dst Port": "dst_port",
            "Protocol": "protocol",
            "Timestamp": "timestamp_raw",
            "Flow Duration": "duration_raw",
            "Total Fwd Packet": "packets_forward",
            "Total Bwd packets": "packets_backward",
            "Total Length of Fwd Packet": "bytes_forward",
            "Total Length of Bwd Packet": "bytes_backward",
            "Flow IAT Mean": "iat_mean",
            "Flow IAT Std": "iat_std",
            "Flow IAT Max": "iat_max",
            "SYN Flag Count": "tcp_syn",
            "ACK Flag Count": "tcp_ack",
            "FIN Flag Count": "tcp_fin",
            "RST Flag Count": "tcp_rst",
            "Fwd Packet Length Mean": "payload_size_mean",
            "Fwd Packet Length Std": "payload_size_std",
            "Label": "label_raw"
        }

        for chunk in pd.read_csv(file_path, chunksize=chunksize, encoding="latin1", on_bad_lines="skip", low_memory=False):
            chunk.columns = [c.strip() for c in chunk.columns]
            use_cols = {orig: target for orig, target in col_map.items() if orig in chunk.columns}
            sub = chunk[list(use_cols.keys())].rename(columns=use_cols).copy()

            # Fast parsing with exact format '%d/%m/%Y %I:%M:%S %p'
            sub["timestamp_normalized"] = pd.to_datetime(sub["timestamp_raw"], format="%d/%m/%Y %I:%M:%S %p", errors="coerce")
            # Fallback for any non-standard rows
            mask_na = sub["timestamp_normalized"].isna()
            if mask_na.any():
                sub.loc[mask_na, "timestamp_normalized"] = pd.to_datetime(sub.loc[mask_na, "timestamp_raw"], format="mixed", errors="coerce")

            sub = sub[sub["timestamp_normalized"].notna()].copy()
            if sub.empty:
                continue

            # Flow Duration: microseconds -> seconds
            sub["duration"] = (sub["duration_raw"].astype(float) / 1e6).clip(lower=0.0)

            sub["packets_forward"] = pd.to_numeric(sub["packets_forward"], errors="coerce").fillna(0).astype(np.uint32)
            sub["packets_backward"] = pd.to_numeric(sub["packets_backward"], errors="coerce").fillna(0).astype(np.uint32)
            sub["bytes_forward"] = pd.to_numeric(sub["bytes_forward"], errors="coerce").fillna(0).astype(np.uint64)
            sub["bytes_backward"] = pd.to_numeric(sub["bytes_backward"], errors="coerce").fillna(0).astype(np.uint64)

            dur_safe = np.maximum(sub["duration"].values, 1e-4)
            sub["packet_rate"] = (sub["packets_forward"] + sub["packets_backward"]) / dur_safe
            sub["byte_rate"] = (sub["bytes_forward"] + sub["bytes_backward"]) / dur_safe

            sub["ttl_mean"] = -1.0
            sub["ttl_std"] = -1.0

            for flag in ["tcp_syn", "tcp_ack", "tcp_fin", "tcp_rst"]:
                if flag in sub.columns:
                    sub[flag] = pd.to_numeric(sub[flag], errors="coerce").fillna(0).astype(np.uint8)
                else:
                    sub[flag] = 0

            labels_str = sub["label_raw"].astype(str).str.strip()
            sub["attack_type"] = labels_str
            sub["label"] = (labels_str.str.lower() != "benign").astype(np.uint8)

            proto_map = {6: "TCP", 17: "UDP", 1: "ICMP", "6": "TCP", "17": "UDP", "1": "ICMP"}
            sub["protocol"] = sub["protocol"].map(proto_map).fillna("OTHER").astype(str)

            sub["dataset"] = "UNSW-NB15"
            sub["scenario_id"] = scenario_id
            sub["derived_approximation"] = False

            sub["src_ip"] = sub["src_ip"].astype(str)
            sub["dst_ip"] = sub["dst_ip"].astype(str)
            src_in = sub["src_ip"].apply(self.boundary.contains).astype(bool)
            dst_in = sub["dst_ip"].apply(self.boundary.contains).astype(bool)
            sub["is_outbound"] = src_in & (~dst_in)
            sub["is_inbound"] = dst_in & (~src_in)

            sub["src_port"] = pd.to_numeric(sub["src_port"], errors="coerce").fillna(0).astype(np.uint16)
            sub["dst_port"] = pd.to_numeric(sub["dst_port"], errors="coerce").fillna(0).astype(np.uint16)

            yield sub


class CTU13Adapter:
    """Adapter for Czech Technical University CTU-13 Binetflow records."""

    def __init__(self, monitored_subnets: Optional[List[str]] = None):
        subnets = monitored_subnets or ["147.32.84.0/24"]
        self.boundary = NetworkBoundaryChecker(subnets)

    def parse_file(self, file_path: str, chunksize: int = 100000) -> Generator[pd.DataFrame, None, None]:
        scen_dir = os.path.basename(os.path.dirname(file_path))
        scenario_id = f"scenario_{int(scen_dir):02d}" if scen_dir.isdigit() else scen_dir

        for chunk in pd.read_csv(file_path, chunksize=chunksize, encoding="latin1", on_bad_lines="skip", low_memory=False):
            chunk.columns = [c.strip() for c in chunk.columns]

            # Parse StartTime with high precision
            chunk["timestamp_raw"] = chunk["StartTime"].astype(str)
            chunk["timestamp_normalized"] = pd.to_datetime(chunk["StartTime"], format="%Y/%m/%d %H:%M:%S.%f", errors="coerce")
            chunk = chunk[chunk["timestamp_normalized"].notna()].copy()

            # Duration is already in seconds in binetflow
            chunk["duration"] = pd.to_numeric(chunk["Dur"], errors="coerce").fillna(0.0).astype(float).clip(lower=0.0)

            # IPs and Ports
            chunk["src_ip"] = chunk["SrcAddr"].astype(str)
            chunk["dst_ip"] = chunk["DstAddr"].astype(str)
            chunk["src_port"] = pd.to_numeric(chunk["Sport"], errors="coerce").fillna(0).astype(np.uint16)
            chunk["dst_port"] = pd.to_numeric(chunk["Dport"], errors="coerce").fillna(0).astype(np.uint16)
            chunk["protocol"] = chunk["Proto"].astype(str).str.upper()

            # Total packets & bytes
            tot_pkts = pd.to_numeric(chunk["TotPkts"], errors="coerce").fillna(1).astype(np.uint32)
            tot_bytes = pd.to_numeric(chunk["TotBytes"], errors="coerce").fillna(0).astype(np.uint64)
            src_bytes = pd.to_numeric(chunk["SrcBytes"], errors="coerce").fillna(0).astype(np.uint64)

            # Directional decomposition:
            # Rule: If Dir == '->', all packets and bytes are forward.
            # If Dir == '<->', derive approximation based on byte ratio, marking derived_approximation=True.
            is_unidir = chunk["Dir"] == "->"
            chunk["derived_approximation"] = ~is_unidir

            pkts_fwd = tot_pkts.copy()
            # For bidirectional flows, compute proportional packets based on SrcBytes / TotBytes
            byte_ratio = np.clip(src_bytes.values / np.maximum(tot_bytes.values, 1), 0.0, 1.0)
            approx_fwd = np.round(tot_pkts.values * byte_ratio).astype(np.uint32)
            # Ensure fwd is at least 1 and at most tot_pkts
            approx_fwd = np.clip(approx_fwd, 1, tot_pkts.values)
            pkts_fwd[~is_unidir] = approx_fwd[~is_unidir]

            chunk["packets_forward"] = pkts_fwd
            chunk["packets_backward"] = (tot_pkts - pkts_fwd).astype(np.uint32)

            chunk["bytes_forward"] = src_bytes
            chunk["bytes_backward"] = np.maximum(0, tot_bytes - src_bytes).astype(np.uint64)

            # Rates
            dur_safe = np.maximum(chunk["duration"].values, 1e-4)
            chunk["packet_rate"] = tot_pkts / dur_safe
            chunk["byte_rate"] = tot_bytes / dur_safe

            # Structurally unavailable fields in Binetflow: IAT, TTL, payload std
            chunk["iat_mean"] = -1.0
            chunk["iat_std"] = -1.0
            chunk["iat_max"] = -1.0
            chunk["ttl_mean"] = -1.0
            chunk["ttl_std"] = -1.0
            chunk["payload_size_std"] = -1.0
            chunk["payload_size_mean"] = (tot_bytes / np.maximum(tot_pkts, 1)).astype(float)

            # Flags derived from Argus State string
            state_str = chunk["State"].astype(str).str.upper()
            chunk["tcp_syn"] = state_str.str.contains("S", regex=False).astype(np.uint8)
            chunk["tcp_ack"] = state_str.str.contains("A", regex=False).astype(np.uint8)
            chunk["tcp_fin"] = state_str.str.contains("F", regex=False).astype(np.uint8)
            chunk["tcp_rst"] = state_str.str.contains("R", regex=False).astype(np.uint8)

            # Labels in CTU-13: 'flow=From-Botnet-V42-UDP-Attempt-DNS', 'flow=Background...', 'flow=Normal...'
            raw_label = chunk["Label"].astype(str)
            is_botnet = raw_label.str.contains("botnet", case=False, regex=False)
            chunk["label"] = is_botnet.astype(np.uint8)

            # Attack type extraction (botnet strain from scenario or label)
            chunk["attack_type"] = "BENIGN"
            chunk.loc[is_botnet, "attack_type"] = "Botnet_" + scenario_id

            chunk["dataset"] = "CTU-13"
            chunk["scenario_id"] = scenario_id

            # Boundary orientation
            src_in = chunk["src_ip"].apply(self.boundary.contains).astype(bool)
            dst_in = chunk["dst_ip"].apply(self.boundary.contains).astype(bool)
            chunk["is_outbound"] = src_in & (~dst_in)
            chunk["is_inbound"] = dst_in & (~src_in)

            yield chunk
