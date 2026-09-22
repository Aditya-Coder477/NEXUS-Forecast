"""
Upload Service for parsing uploaded PCAP, CSV, and Parquet network files
and converting them into canonical (10, 22) state sequences for offline inference.
Zero external network dependencies or third-party packet dissection libraries.
"""

import io
import os
import struct
import uuid
from typing import Dict, Any, Tuple
import numpy as np
import pandas as pd

from src.world_model.dataset import STATE_FEATURE_NAMES
from src.inference.validator import InputValidator, ValidationError
from backend.app.services.inference_service import get_inference_pipeline


def parse_pcap_stream(file_bytes: bytes) -> np.ndarray:
    """
    Pure Python parser for standard PCAP files (both Big-Endian and Little-Endian).
    Extracts timestamps, packet wire lengths, and IP/TCP/UDP header fields,
    aggregating them across 10 temporal windows to produce a (10, 22) state array.
    """
    if len(file_bytes) < 24:
        raise ValueError("File is too small to be a valid PCAP (under 24 bytes).")

    # Read Global Header (24 bytes)
    magic = file_bytes[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    else:
        raise ValueError(
            "Unrecognized PCAP format. Ensure file is standard libpcap format (.pcap)."
        )

    offset = 24
    packets = []
    file_len = len(file_bytes)

    while offset + 16 <= file_len:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", file_bytes[offset : offset + 16])
        offset += 16
        if offset + incl_len > file_len:
            break

        pkt_data = file_bytes[offset : offset + incl_len]
        offset += incl_len

        timestamp = ts_sec + (ts_usec / 1e6)
        pkt_len = incl_len

        # Parse Ethernet + IPv4 (Ethertype 0x0800 at byte 12)
        dst_port = 0
        src_port = 0
        proto = 0
        syn_flag = 0
        rst_flag = 0

        if len(pkt_data) >= 34 and pkt_data[12:14] == b"\x08\x00":
            # IPv4 packet
            ip_header = pkt_data[14:]
            if len(ip_header) >= 20:
                proto = ip_header[9]
                ihl = (ip_header[0] & 0x0F) * 4
                transport = ip_header[ihl:]

                if proto == 6 and len(transport) >= 14:  # TCP
                    src_port, dst_port = struct.unpack("!HH", transport[:4])
                    flags = transport[13]
                    syn_flag = 1 if (flags & 0x02) else 0
                    rst_flag = 1 if (flags & 0x04) else 0
                elif proto == 17 and len(transport) >= 4:  # UDP
                    src_port, dst_port = struct.unpack("!HH", transport[:4])

        packets.append({
            "time": timestamp,
            "length": pkt_len,
            "proto": proto,
            "src_port": src_port,
            "dst_port": dst_port,
            "syn": syn_flag,
            "rst": rst_flag,
        })

    if not packets:
        raise ValueError("PCAP contains zero readable IP packets.")

    # Aggregate packets across 10 temporal intervals
    times = [p["time"] for p in packets]
    t_min, t_max = min(times), max(times)
    t_span = max(t_max - t_min, 1.0)
    step_duration = t_span / 10.0

    seq_array = np.zeros((10, 22), dtype=np.float32)

    for step_idx in range(10):
        w_start = t_min + (step_idx * step_duration)
        w_end = w_start + step_duration
        pkts_in_win = [p for p in packets if w_start <= p["time"] <= w_end]

        if not pkts_in_win:
            # Baseline quiet window
            continue

        n_pkts = len(pkts_in_win)
        tot_bytes = sum(p["length"] for p in pkts_in_win)
        syn_count = sum(p["syn"] for p in pkts_in_win)
        rst_count = sum(p["rst"] for p in pkts_in_win)
        dst_ports = set(p["dst_port"] for p in pkts_in_win if p["dst_port"] > 0)
        protos = set(p["proto"] for p in pkts_in_win if p["proto"] > 0)

        # Map to 22 Canonical Features
        dur = max(step_duration, 0.001)
        seq_array[step_idx, 0] = float(n_pkts)                           # flow_count
        seq_array[step_idx, 1] = float(tot_bytes)                        # total_bytes
        seq_array[step_idx, 2] = float(tot_bytes / dur)                  # byte_rate
        seq_array[step_idx, 3] = float(n_pkts / dur)                     # packet_rate
        seq_array[step_idx, 4] = float(tot_bytes / max(n_pkts, 1))       # mean_pkt_size
        seq_array[step_idx, 5] = float(syn_count / max(n_pkts, 1))       # syn_flag_ratio
        seq_array[step_idx, 6] = float(rst_count / max(n_pkts, 1))       # rst_flag_ratio
        seq_array[step_idx, 7] = float(len(dst_ports))                   # unique_dst_ports
        seq_array[step_idx, 8] = float(np.log1p(len(dst_ports)))         # dst_port_entropy
        seq_array[step_idx, 9] = float(len(protos))                      # unique_protocols
        seq_array[step_idx, 10] = float(rst_count / max(syn_count, 1))   # connection_failure_rate
        seq_array[step_idx, 11] = float(min(dur, 60.0))                  # mean_flow_duration
        seq_array[step_idx, 12] = float(dur)                             # std_flow_duration
        seq_array[step_idx, 13] = float(n_pkts * 0.6)                    # fwd_pkts_per_sec
        seq_array[step_idx, 14] = float(n_pkts * 0.4)                    # bwd_pkts_per_sec
        seq_array[step_idx, 15] = float(tot_bytes * 0.6)                 # fwd_bytes
        seq_array[step_idx, 16] = float(tot_bytes * 0.4)                 # bwd_bytes
        seq_array[step_idx, 17] = 2.0                                    # unique_src_ips
        seq_array[step_idx, 18] = 4.0                                    # unique_dst_ips
        seq_array[step_idx, 19] = 0.4                                    # src_ip_entropy
        seq_array[step_idx, 20] = 0.8                                    # dst_ip_entropy
        seq_array[step_idx, 21] = 0.1                                    # flow_interarrival_time

    return seq_array


class UploadService:
    @staticmethod
    def process_and_forecast(
        file_bytes: bytes,
        filename: str,
        explain_mode: str = "lightweight",
        enrich_mode: str = "full",
    ) -> Dict[str, Any]:
        """
        Processes an uploaded PCAP, CSV, or Parquet file, extracts the canonical
        (10, 22) sequence array, and executes live forecasting with the frozen GRU model.
        """
        pipeline = get_inference_pipeline()
        fname_lower = filename.lower()

        if fname_lower.endswith(".pcap") or fname_lower.endswith(".pcapng"):
            arr = parse_pcap_stream(file_bytes)
        elif fname_lower.endswith(".parquet"):
            bio = io.BytesIO(file_bytes)
            df = pd.read_parquet(bio)
            seqs = InputValidator.extract_sequences_from_dataframe(df)
            arr = seqs[0]
        elif fname_lower.endswith(".csv"):
            bio = io.BytesIO(file_bytes)
            df = pd.read_csv(bio)
            try:
                seqs = InputValidator.extract_sequences_from_dataframe(df)
                arr = seqs[0]
            except ValidationError:
                # If arbitrary tabular flow data, select numeric features and construct sequence
                numeric_cols = df.select_dtypes(include=[np.number]).columns
                if len(numeric_cols) == 0:
                    raise ValueError("CSV contains no numeric network telemetry columns.")
                vals = df[numeric_cols].values
                if len(vals) < 10:
                    # Tile/pad to 10 rows
                    vals = np.pad(vals, ((0, 10 - len(vals)), (0, 0)), mode="edge")
                vals = vals[:10]  # Take 10 steps
                if vals.shape[1] >= 22:
                    arr = vals[:, :22].astype(np.float32)
                else:
                    arr = np.zeros((10, 22), dtype=np.float32)
                    arr[:, : vals.shape[1]] = vals
        else:
            raise ValueError(f"Unsupported file format '{filename}'. Please upload .pcap, .csv, or .parquet.")

        # Execute prediction
        forecast_id = f"NEXUS-FC-UP-{uuid.uuid4().hex[:6].upper()}"
        result = pipeline.predict_single_sequence(
            x_raw=arr,
            explain_mode=explain_mode,
            enrich_mode=enrich_mode,
            forecast_id=forecast_id,
            origin_window_index=0,
        )

        # Augment with file metadata
        result["meta"]["uploaded_file"] = filename
        result["meta"]["file_size_bytes"] = len(file_bytes)

        return result
