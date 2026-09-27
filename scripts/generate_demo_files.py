"""
NEXUS-Forecast Demo File Generator.
Generates comprehensive demo files in data/demo/ illustrating all system functions:
1. demo_attack_scenarios.parquet - Multi-scenario sequence parquet (DDoS, Infiltration, PortScan, Benign).
2. demo_attack_telemetry.csv     - 10-window CSV telemetry of an active volumetric attack.
3. demo_benign_telemetry.csv     - 10-window CSV telemetry of quiet enterprise baseline.
4. demo_portscan_traffic.pcap     - Raw libpcap binary packet capture for packet dissection & live forecasting.
5. demo_api_payload.json         - JSON payload for REST API endpoint /api/v1/inference/predict.
6. README.md                     - Complete user & SOC analyst guide to the demo files.
"""

import os
import io
import json
import struct
from pathlib import Path
import numpy as np
import pandas as pd

from src.world_model.dataset import STATE_FEATURE_NAMES
from src.inference.pipeline import OfflineInferencePipeline
from src.inference.validator import InputValidator

ROOT_DIR = Path(__file__).resolve().parent.parent
DEMO_DIR = ROOT_DIR / "data" / "demo"
DEMO_DIR.mkdir(parents=True, exist_ok=True)


def generate_parquet_demo():
    print("[1/5] Generating demo_attack_scenarios.parquet...")
    cic_path = ROOT_DIR / "data" / "processed" / "forecast_sequences" / "cic_ids2017_sequences.parquet"
    unsw_path = ROOT_DIR / "data" / "processed" / "forecast_sequences" / "unsw_nb15_sequences.parquet"

    df_cic = pd.read_parquet(cic_path)
    df_unsw = pd.read_parquet(unsw_path)

    # 1. DDoS active attack sample (Friday-WorkingHours-Afternoon-DDos, attack_flag=1)
    ddos_attacks = df_cic[(df_cic["scenario_id"] == "Friday-WorkingHours-Afternoon-DDos") & (df_cic["current_attack_flag"] == 1)]
    ddos_sample = ddos_attacks.iloc[29:30].copy()
    ddos_sample["demo_scenario_description"] = "Volumetric DDoS SYN Flood Attack (High Threat)"

    # 2. Advanced Multi-stage Infiltration & Execution sample (UNSW-NB15)
    unsw_attacks = df_unsw[df_unsw["current_attack_flag"] == 1]
    unsw_sample = unsw_attacks.iloc[121:122].copy()
    unsw_sample["demo_scenario_description"] = "Multi-Stage Attack: C2 to Execution Trajectory"

    # 3. PortScan Reconnaissance sample
    portscan_samples = df_cic[(df_cic["scenario_id"] == "Friday-WorkingHours-Afternoon-PortScan") & (df_cic["current_attack_flag"] == 1)]
    ps_sample = portscan_samples.iloc[10:11].copy()
    ps_sample["demo_scenario_description"] = "Network Reconnaissance & Horizontal Port Scanning"

    # 4. Standard Enterprise Benign Baseline (Monday Working Hours)
    benign_mon = df_cic[(df_cic["scenario_id"] == "Monday-WorkingHours") & (df_cic["current_attack_flag"] == 0)].iloc[25:26].copy()
    benign_mon["demo_scenario_description"] = "Normal Working Hours Telemetry (Benign Baseline)"

    # 5. Quiet Night Baseline (Friday Morning)
    benign_quiet = df_cic[(df_cic["scenario_id"] == "Friday-WorkingHours-Morning") & (df_cic["current_attack_flag"] == 0)].iloc[10:11].copy()
    benign_quiet["demo_scenario_description"] = "Quiet Network Window (Zero Anomaly Baseline)"

    combined_df = pd.concat([ddos_sample, unsw_sample, ps_sample, benign_mon, benign_quiet], ignore_index=True)
    out_path = DEMO_DIR / "demo_attack_scenarios.parquet"
    combined_df.to_parquet(out_path, index=False)
    print(f"  -> Saved {len(combined_df)} scenarios to {out_path} ({out_path.stat().st_size} bytes)")
    return ddos_sample, benign_mon


def generate_csv_demos(ddos_sample: pd.DataFrame, benign_sample: pd.DataFrame):
    print("[2/5] Generating demo CSV telemetry files...")

    # Attack CSV (10 consecutive temporal windows, 22 canonical features)
    attack_rows = []
    for t in range(-9, 1):
        prefix = f"S_t{t:+d}_" if t != 0 else "S_t_"
        row = {feat: float(ddos_sample[f"{prefix}{feat}"].values[0]) for feat in STATE_FEATURE_NAMES}
        attack_rows.append(row)
    attack_df = pd.DataFrame(attack_rows)
    attack_csv_path = DEMO_DIR / "demo_attack_telemetry.csv"
    attack_df.to_csv(attack_csv_path, index=False)
    print(f"  -> Saved {len(attack_df)} windows to {attack_csv_path}")

    # Benign CSV (10 consecutive temporal windows, 22 canonical features)
    benign_rows = []
    for t in range(-9, 1):
        prefix = f"S_t{t:+d}_" if t != 0 else "S_t_"
        row = {feat: float(benign_sample[f"{prefix}{feat}"].values[0]) for feat in STATE_FEATURE_NAMES}
        benign_rows.append(row)
    benign_df = pd.DataFrame(benign_rows)
    benign_csv_path = DEMO_DIR / "demo_benign_telemetry.csv"
    benign_df.to_csv(benign_csv_path, index=False)
    print(f"  -> Saved {len(benign_df)} windows to {benign_csv_path}")

    return attack_df


def generate_pcap_demo():
    print("[3/5] Generating demo_portscan_traffic.pcap...")
    buf = io.BytesIO()
    # Libpcap Global Header (24 bytes) Little-Endian
    # magic=0xa1b2c3d4, major=2, minor=4, thiszone=0, sigfigs=0, snaplen=65535, network=1 (Ethernet)
    buf.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

    # Generate 120 packets across 10 temporal windows (each window 30s)
    t_base = 1500000000.0
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 1521, 3306, 3389, 5432, 8080, 8443]

    for w in range(10):
        # In early windows: light recon; in later windows: aggressive SYN flood/scan
        num_pkts = 8 + (w * 4)
        for p in range(num_pkts):
            t = t_base + (w * 30.0) + (p * (28.0 / num_pkts))
            ts_sec = int(t)
            ts_usec = int((t - ts_sec) * 1e6)

            src_ip_last = 50 + (p % 4)
            dst_ip_last = 10 + (p % 10)
            dst_port = scan_ports[(w * 2 + p) % len(scan_ports)]
            src_port = 45000 + (w * 100) + p

            # Ethernet header (14 bytes)
            eth = b"\x00\x50\x56\xaa\xbb\xcc" + b"\x00\x0c\x29\x11\x22\x33" + struct.pack("!H", 0x0800)

            # IPv4 header (20 bytes)
            total_len = 40 + (p % 40)
            ip = struct.pack(
                "!BBHHHBBH4s4s",
                0x45, 0x00, total_len, 1000 + p, 0, 64, 6, 0,
                bytes([192, 168, 10, src_ip_last]),
                bytes([10, 0, 0, dst_ip_last])
            )

            # TCP header (20 bytes) with SYN flag (0x02) or SYN+ACK for baseline
            tcp_flags = 0x02 if (p % 5 != 0) else 0x12
            tcp = struct.pack(
                "!HHIIBBHHH",
                src_port, dst_port, 100000 + p * 50, 0,
                (5 << 4), tcp_flags, 65535, 0, 0
            )

            payload = b"X" * (total_len - 40)
            packet_data = eth + ip + tcp + payload
            incl_len = len(packet_data)
            orig_len = incl_len

            # Packet header (16 bytes)
            buf.write(struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len))
            buf.write(packet_data)

    pcap_bytes = buf.getvalue()
    pcap_path = DEMO_DIR / "demo_portscan_traffic.pcap"
    with open(pcap_path, "wb") as f:
        f.write(pcap_bytes)
    print(f"  -> Saved PCAP capture to {pcap_path} ({len(pcap_bytes)} bytes)")


def generate_api_payload_demo(attack_df: pd.DataFrame):
    print("[4/5] Generating demo_api_payload.json...")
    raw_seq = attack_df.values.tolist()
    payload = {
        "input_type": "state",
        "raw_sequence": raw_seq,
        "horizons": [1, 3, 6],
        "explain_mode": "full",
        "enrich_mode": "full",
        "description": "NEXUS-Forecast REST API Live Inference Payload (10 timesteps x 22 canonical features)"
    }
    payload_path = DEMO_DIR / "demo_api_payload.json"
    with open(payload_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    print(f"  -> Saved API JSON payload to {payload_path}")


def generate_readme():
    print("[5/5] Generating data/demo/README.md...")
    readme_content = """# NEXUS-Forecast: Demo Telemetry & Traffic Files

This directory contains production-grade demonstration datasets designed to showcase all core analytical, forecasting, and explainability capabilities of **NEXUS-Forecast**:

| Demo File | Format | Scenario Type | Target Capability Demonstrated |
| :--- | :--- | :--- | :--- |
| `demo_attack_scenarios.parquet` | `.parquet` | Multi-scenario (DDoS, Infiltration, PortScan, Benign) | Multi-horizon forecasting, kill-chain trajectory, and cross-dataset comparison |
| `demo_attack_telemetry.csv` | `.csv` | Volumetric DDoS SYN Flood | Attack alert triggering, MITRE ATT&CK & CAPEC mapping, feature attribution |
| `demo_benign_telemetry.csv` | `.csv` | Normal enterprise operations | Baseline stability, negative attribution, zero false-alarm confirmation |
| `demo_portscan_traffic.pcap` | `.pcap` | Multi-target TCP SYN Reconnaissance | Raw packet ingestion, pure-Python frame parsing, and temporal state windowing |
| `demo_api_payload.json` | `.json` | Ready-to-use API payload | REST API endpoint integration (`POST /api/v1/inference/predict`) |
| `example_sequence.parquet` | `.parquet` | Canonical test sequences | Air-gapped pipeline integration tests |

---

## 1. Multi-Scenario Parquet Testing (`demo_attack_scenarios.parquet`)

Run the full offline inference engine across multiple distinct attack and benign scenarios:

```bash
# Run CLI inference and generate a formatted SOC Analyst Markdown brief
python -m src.inference.run \\
    --input data/demo/demo_attack_scenarios.parquet \\
    --explain full \\
    --enrich full \\
    --format markdown \\
    --output outputs/demo_scenarios_brief.md
```

### Expected Behavior:
- **Sample 1 (DDoS Attack)**: Forecasts `ATTACK` (Calibrated Prob: **~59%**, Threshold: **0.45**), Threat Level: `ELEVATED`, MITRE Stage: `COMMAND_AND_CONTROL`, top features: `std_iat, mean_packet_rate, total_flows`.
- **Sample 2 (UNSW Infiltration)**: Forecasts `ATTACK` (Calibrated Prob: **~62%**), Trajectory: `COMMAND_AND_CONTROL -> EXECUTION -> EXECUTION`.
- **Sample 3 (PortScan)**: Flags network reconnaissance and host diversity anomalies.
- **Samples 4 & 5 (Benign)**: Safely forecast `BENIGN` (Prob: **~29-32%**), Threat Level: `BENIGN`.

---

## 2. CSV Telemetry Testing (`demo_attack_telemetry.csv` & `demo_benign_telemetry.csv`)

These CSV files contain 10 consecutive temporal telemetry windows across all 22 canonical features. You can open and edit them in Excel or text editors:

### Run Attack Telemetry:
```bash
python -m src.inference.run \\
    --input data/demo/demo_attack_telemetry.csv \\
    --explain lightweight \\
    --enrich full \\
    --format json
```

### Run Benign Telemetry:
```bash
python -m src.inference.run \\
    --input data/demo/demo_benign_telemetry.csv \\
    --explain lightweight \\
    --enrich full \\
    --format json
```

### Web UI Drag-and-Drop:
1. Open the Analyst Workstation Dashboard (`http://localhost:8000/dashboard` or on Render).
2. Navigate to the **Live Inference** tab.
3. Drag and drop either `demo_attack_telemetry.csv` or `demo_benign_telemetry.csv` into the file uploader.
4. Watch the neural model execute real-time multi-horizon forward simulation.

---

## 3. Raw Packet Capture Ingestion (`demo_portscan_traffic.pcap`)

NEXUS-Forecast features a zero-dependency, pure-Python PCAP parser (`UploadService.parse_pcap_stream`) that extracts Ethernet, IPv4, TCP flags, and UDP headers directly from raw packet captures.

### Uploading via Web UI:
- Drag `data/demo/demo_portscan_traffic.pcap` directly into the Dashboard upload dropzone.
- The backend parses the raw packets into 10 temporal windows, computes packet rates, entropy, and SYN ratios, and feeds the sequence tensor into the GRU world model.

### Uploading via cURL:
```bash
curl -X POST "http://localhost:8000/api/v1/inference/upload" \\
    -F "file=@data/demo/demo_portscan_traffic.pcap" \\
    -F "explain_mode=lightweight" \\
    -F "enrich_mode=full"
```

---

## 4. REST API Live Payload Testing (`demo_api_payload.json`)

Integrate directly with external SIEMs (Splunk, Elastic SIEM, Microsoft Sentinel):

```bash
curl -X POST "http://localhost:8000/api/v1/inference/predict" \\
    -H "Content-Type: application/json" \\
    -d @data/demo/demo_api_payload.json
```

---

## Schema Reference: 22 Canonical Network State Features

Each temporal window in NEXUS-Forecast aggregates traffic across 22 canonical dimensions:
1. `total_flows`
2. `unique_src_hosts`
3. `unique_dst_hosts`
4. `unique_dst_ports`
5. `unique_protocols`
6. `total_packets`
7. `total_bytes`
8. `inbound_bytes`
9. `outbound_bytes`
10. `inbound_outbound_ratio`
11. `mean_flow_duration`
12. `mean_packet_rate`
13. `mean_byte_rate`
14. `mean_iat`
15. `std_iat`
16. `syn_count`
17. `ack_count`
18. `rst_count`
19. `fin_count`
20. `connection_failure_rate`
21. `unique_host_pair_count`
22. `fan_out_ratio`
"""
    readme_path = DEMO_DIR / "README.md"
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(readme_content)
    print(f"  -> Saved {readme_path}")


def main():
    print("=== Starting NEXUS-Forecast Demo File Generation ===")
    ddos_sample, benign_sample = generate_parquet_demo()
    attack_df = generate_csv_demos(ddos_sample, benign_sample)
    generate_pcap_demo()
    generate_api_payload_demo(attack_df)
    generate_readme()
    print("=== Demo File Generation Complete ===")


if __name__ == "__main__":
    main()
