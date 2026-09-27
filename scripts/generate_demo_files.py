"""
NEXUS-Forecast Demo File Generator.
Generates an expanded, comprehensive suite of demo files in data/demo/ illustrating all system functions:

1. Parquet Scenarios:
   - demo_attack_scenarios.parquet       (CIC-IDS2017 & UNSW-NB15 multi-scenario: DDoS, PortScan, Infiltration, Benign)
   - demo_ctu13_botnet_scenarios.parquet (CTU-13 Neris & RBot botnet command-and-control sequences)
   - demo_unsw_nb15_scenarios.parquet    (UNSW-NB15 multi-stage exploits & lateral movement)

2. CSV Telemetry Files (10 temporal steps x 22 canonical features):
   - demo_attack_telemetry.csv           (Volumetric DDoS SYN Flood)
   - demo_benign_telemetry.csv           (Quiet enterprise baseline)
   - demo_botnet_ctu13.csv               (CTU-13 Neris Botnet periodic C2 beaconing)
   - demo_web_attacks.csv                (CIC-IDS2017 Web Brute Force & SQL Injection)
   - demo_infiltration_lateral.csv       (CIC-IDS2017 Infiltration & Internal Reconnaissance)
   - demo_unsw_multistage.csv            (UNSW-NB15 Multi-Stage Exploit Progression)

3. Raw Binary Packet Captures (.pcap):
   - demo_portscan_traffic.pcap          (Multi-target TCP SYN Reconnaissance scan)
   - demo_synflood_traffic.pcap          (Targeted TCP SYN Flood against HTTP/HTTPS ports)
   - demo_dns_amplification.pcap         (Heavy UDP DNS reflection/amplification traffic)

4. REST API Payloads (.json):
   - demo_api_payload.json               (Active attack sequence payload)
   - demo_benign_payload.json            (Quiet baseline sequence payload)
   - demo_botnet_payload.json            (Botnet C2 sequence payload)

5. Documentation:
   - README.md                           (Complete analyst guide for all demo files)
"""

import io
import sys
import json
import struct
from pathlib import Path
import numpy as np
import pandas as pd

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.world_model.dataset import STATE_FEATURE_NAMES
DEMO_DIR = ROOT_DIR / "data" / "demo"
DEMO_DIR.mkdir(parents=True, exist_ok=True)


def extract_10step_df(sample_row: pd.DataFrame) -> pd.DataFrame:
    """Extract 10 consecutive temporal windows x 22 features from a sequence row."""
    rows = []
    for t in range(-9, 1):
        prefix = f"S_t{t:+d}_" if t != 0 else "S_t_"
        row = {feat: float(sample_row[f"{prefix}{feat}"].values[0]) for feat in STATE_FEATURE_NAMES}
        rows.append(row)
    return pd.DataFrame(rows)


def generate_parquet_demos():
    print("[1/5] Generating Parquet demo files...")
    cic_path = ROOT_DIR / "data" / "processed" / "forecast_sequences" / "cic_ids2017_sequences.parquet"
    ctu_path = ROOT_DIR / "data" / "processed" / "forecast_sequences" / "ctu13_sequences.parquet"
    unsw_path = ROOT_DIR / "data" / "processed" / "forecast_sequences" / "unsw_nb15_sequences.parquet"

    df_cic = pd.read_parquet(cic_path)
    df_ctu = pd.read_parquet(ctu_path)
    df_unsw = pd.read_parquet(unsw_path)

    # 1. Multi-scenario parquet (CIC + UNSW)
    ddos_sample = df_cic[(df_cic["scenario_id"] == "Friday-WorkingHours-Afternoon-DDos") & (df_cic["current_attack_flag"] == 1)].iloc[29:30].copy()
    ddos_sample["demo_scenario_description"] = "Volumetric DDoS SYN Flood Attack (High Threat)"

    unsw_attacks = df_unsw[df_unsw["current_attack_flag"] == 1]
    unsw_sample = unsw_attacks.iloc[121:122].copy()
    unsw_sample["demo_scenario_description"] = "Multi-Stage Attack: C2 to Execution Trajectory"

    portscan_sample = df_cic[(df_cic["scenario_id"] == "Friday-WorkingHours-Afternoon-PortScan") & (df_cic["current_attack_flag"] == 1)].iloc[10:11].copy()
    portscan_sample["demo_scenario_description"] = "Network Reconnaissance & Horizontal Port Scanning"

    benign_mon = df_cic[(df_cic["scenario_id"] == "Monday-WorkingHours") & (df_cic["current_attack_flag"] == 0)].iloc[25:26].copy()
    benign_mon["demo_scenario_description"] = "Normal Working Hours Telemetry (Benign Baseline)"

    benign_quiet = df_cic[(df_cic["scenario_id"] == "Friday-WorkingHours-Morning") & (df_cic["current_attack_flag"] == 0)].iloc[10:11].copy()
    benign_quiet["demo_scenario_description"] = "Quiet Network Window (Zero Anomaly Baseline)"

    scenarios_df = pd.concat([ddos_sample, unsw_sample, portscan_sample, benign_mon, benign_quiet], ignore_index=True)
    scenarios_path = DEMO_DIR / "demo_attack_scenarios.parquet"
    scenarios_df.to_parquet(scenarios_path, index=False)
    print(f"  -> Saved {len(scenarios_df)} scenarios to {scenarios_path.name}")

    # 2. CTU-13 Botnet scenarios parquet
    ctu_sc01_att = df_ctu[(df_ctu["scenario_id"] == "scenario_01") & (df_ctu["current_attack_flag"] == 1)].iloc[10:12].copy()
    ctu_sc03_att = df_ctu[(df_ctu["scenario_id"] == "scenario_03") & (df_ctu["current_attack_flag"] == 1)].iloc[20:22].copy()
    ctu_benign = df_ctu[(df_ctu["scenario_id"] == "scenario_01") & (df_ctu["current_attack_flag"] == 0)].iloc[5:6].copy()
    ctu_df = pd.concat([ctu_sc01_att, ctu_sc03_att, ctu_benign], ignore_index=True)
    ctu_path_out = DEMO_DIR / "demo_ctu13_botnet_scenarios.parquet"
    ctu_df.to_parquet(ctu_path_out, index=False)
    print(f"  -> Saved {len(ctu_df)} CTU-13 scenarios to {ctu_path_out.name}")

    # 3. UNSW-NB15 Scenarios parquet
    unsw_att_multi = df_unsw[df_unsw["current_attack_flag"] == 1].iloc[50:53].copy()
    unsw_ben_multi = df_unsw[df_unsw["current_attack_flag"] == 0].iloc[10:12].copy()
    unsw_df = pd.concat([unsw_att_multi, unsw_ben_multi], ignore_index=True)
    unsw_path_out = DEMO_DIR / "demo_unsw_nb15_scenarios.parquet"
    unsw_df.to_parquet(unsw_path_out, index=False)
    print(f"  -> Saved {len(unsw_df)} UNSW-NB15 scenarios to {unsw_path_out.name}")

    # Also extract specific samples for CSV generation
    web_sample = df_cic[(df_cic["scenario_id"] == "Thursday-WorkingHours-Morning-WebAttacks") & (df_cic["current_attack_flag"] == 1)].iloc[15:16].copy()
    infil_sample = df_cic[(df_cic["scenario_id"] == "Thursday-WorkingHours-Afternoon-Infilteration") & (df_cic["current_attack_flag"] == 1)].iloc[20:21].copy()
    botnet_sample = ctu_sc01_att.iloc[0:1].copy()
    unsw_single = unsw_sample.iloc[0:1].copy()

    return {
        "ddos": ddos_sample,
        "benign": benign_mon,
        "web": web_sample,
        "infil": infil_sample,
        "botnet": botnet_sample,
        "unsw": unsw_single,
    }


def generate_csv_demos(samples: dict):
    print("[2/5] Generating CSV telemetry files...")

    # 1. DDoS Attack
    df_ddos = extract_10step_df(samples["ddos"])
    df_ddos.to_csv(DEMO_DIR / "demo_attack_telemetry.csv", index=False)
    print("  -> Saved demo_attack_telemetry.csv")

    # 2. Benign Baseline
    df_benign = extract_10step_df(samples["benign"])
    df_benign.to_csv(DEMO_DIR / "demo_benign_telemetry.csv", index=False)
    print("  -> Saved demo_benign_telemetry.csv")

    # 3. CTU-13 Botnet (Neris)
    df_botnet = extract_10step_df(samples["botnet"])
    df_botnet.to_csv(DEMO_DIR / "demo_botnet_ctu13.csv", index=False)
    print("  -> Saved demo_botnet_ctu13.csv")

    # 4. Web Attacks (Brute Force / SQLi)
    df_web = extract_10step_df(samples["web"])
    df_web.to_csv(DEMO_DIR / "demo_web_attacks.csv", index=False)
    print("  -> Saved demo_web_attacks.csv")

    # 5. Infiltration & Lateral Movement
    df_infil = extract_10step_df(samples["infil"])
    df_infil.to_csv(DEMO_DIR / "demo_infiltration_lateral.csv", index=False)
    print("  -> Saved demo_infiltration_lateral.csv")

    # 6. UNSW Multi-stage Attack
    df_unsw = extract_10step_df(samples["unsw"])
    df_unsw.to_csv(DEMO_DIR / "demo_unsw_multistage.csv", index=False)
    print("  -> Saved demo_unsw_multistage.csv")

    return df_ddos, df_benign, df_botnet


def generate_pcap_demos():
    print("[3/5] Generating PCAP capture files...")

    # Helper to build a standard libpcap header (24 bytes)
    def pcap_header():
        return struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    # 1. PortScan PCAP
    buf_ps = io.BytesIO()
    buf_ps.write(pcap_header())
    t_base = 1500000000.0
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 1521, 3306, 3389, 5432, 8080, 8443]

    for w in range(10):
        num_pkts = 8 + (w * 4)
        for p in range(num_pkts):
            t = t_base + (w * 30.0) + (p * (28.0 / num_pkts))
            ts_sec = int(t)
            ts_usec = int((t - ts_sec) * 1e6)
            dst_port = scan_ports[(w * 2 + p) % len(scan_ports)]
            src_port = 45000 + (w * 100) + p

            eth = b"\x00\x50\x56\xaa\xbb\xcc\x00\x0c\x29\x11\x22\x33\x08\x00"
            total_len = 40 + (p % 40)
            ip = struct.pack(
                "!BBHHHBBH4s4s",
                0x45, 0x00, total_len, 1000 + p, 0, 64, 6, 0,
                bytes([192, 168, 10, 50 + (p % 4)]),
                bytes([10, 0, 0, 10 + (p % 10)])
            )
            tcp_flags = 0x02 if (p % 5 != 0) else 0x12
            tcp = struct.pack("!HHIIBBHHH", src_port, dst_port, 100000 + p * 50, 0, (5 << 4), tcp_flags, 65535, 0, 0)
            payload = b"X" * (total_len - 40)
            pkt = eth + ip + tcp + payload
            buf_ps.write(struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt)))
            buf_ps.write(pkt)

    with open(DEMO_DIR / "demo_portscan_traffic.pcap", "wb") as f:
        f.write(buf_ps.getvalue())
    print("  -> Saved demo_portscan_traffic.pcap")

    # 2. SYN Flood PCAP (Heavy volumetric TCP SYN attack targeting web services)
    buf_syn = io.BytesIO()
    buf_syn.write(pcap_header())
    for w in range(10):
        # Accelerating rate across temporal windows (simulating flood surge)
        num_pkts = 20 + (w * 15)
        for p in range(num_pkts):
            t = t_base + (w * 30.0) + (p * (29.0 / num_pkts))
            ts_sec = int(t)
            ts_usec = int((t - ts_sec) * 1e6)
            dst_port = 80 if (p % 2 == 0) else 443
            src_port = 10000 + ((p * 37) % 55000)

            eth = b"\x00\x50\x56\xaa\xbb\xcc\x00\x0c\x29\x44\x55\x66\x08\x00"
            total_len = 44
            ip = struct.pack(
                "!BBHHHBBH4s4s",
                0x45, 0x00, total_len, 2000 + p, 0, 64, 6, 0,
                bytes([172, 16, (p % 16), 10 + (p % 200)]),
                bytes([192, 168, 1, 100])
            )
            # Pure SYN flag (0x02)
            tcp = struct.pack("!HHIIBBHHH", src_port, dst_port, 500000 + p * 100, 0, (6 << 4), 0x02, 64240, 0, 0)
            payload = b"\x02\x04\x05\xb4"  # MSS option
            pkt = eth + ip + tcp + payload
            buf_syn.write(struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt)))
            buf_syn.write(pkt)

    with open(DEMO_DIR / "demo_synflood_traffic.pcap", "wb") as f:
        f.write(buf_syn.getvalue())
    print("  -> Saved demo_synflood_traffic.pcap")

    # 3. DNS Amplification PCAP (Heavy UDP Port 53 reflection flood)
    buf_dns = io.BytesIO()
    buf_dns.write(pcap_header())
    for w in range(10):
        num_pkts = 15 + (w * 10)
        for p in range(num_pkts):
            t = t_base + (w * 30.0) + (p * (29.0 / num_pkts))
            ts_sec = int(t)
            ts_usec = int((t - ts_sec) * 1e6)
            src_port = 53  # DNS Server
            dst_port = 30000 + (p % 10000)

            eth = b"\x00\x50\x56\xaa\xbb\xcc\x00\x0c\x29\x77\x88\x99\x08\x00"
            dns_payload_len = 512 + (p % 256)
            udp_len = 8 + dns_payload_len
            total_len = 20 + udp_len

            ip = struct.pack(
                "!BBHHHBBH4s4s",
                0x45, 0x00, total_len, 3000 + p, 0, 64, 17, 0,  # 17 = UDP
                bytes([8, 8, 8, 8]),
                bytes([192, 168, 1, 50])
            )
            udp = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
            payload = b"\xaa\xbb\x81\x80" + (b"\x00" * (dns_payload_len - 4))
            pkt = eth + ip + udp + payload
            buf_dns.write(struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt)))
            buf_dns.write(pkt)

    with open(DEMO_DIR / "demo_dns_amplification.pcap", "wb") as f:
        f.write(buf_dns.getvalue())
    print("  -> Saved demo_dns_amplification.pcap")


def generate_json_payloads(df_ddos: pd.DataFrame, df_benign: pd.DataFrame, df_botnet: pd.DataFrame):
    print("[4/5] Generating JSON REST API payloads...")

    # 1. Active DDoS Attack Payload
    p_attack = {
        "input_type": "state",
        "raw_sequence": df_ddos.values.tolist(),
        "horizons": [1, 3, 6],
        "explain_mode": "full",
        "enrich_mode": "full",
        "description": "NEXUS-Forecast REST API Active Attack Payload (Volumetric DDoS SYN Flood)"
    }
    with open(DEMO_DIR / "demo_api_payload.json", "w", encoding="utf-8") as f:
        json.dump(p_attack, f, indent=2)
    print("  -> Saved demo_api_payload.json")

    # 2. Benign Baseline Payload
    p_benign = {
        "input_type": "state",
        "raw_sequence": df_benign.values.tolist(),
        "horizons": [1, 3, 6],
        "explain_mode": "lightweight",
        "enrich_mode": "full",
        "description": "NEXUS-Forecast REST API Benign Baseline Payload (Normal Enterprise Working Hours)"
    }
    with open(DEMO_DIR / "demo_benign_payload.json", "w", encoding="utf-8") as f:
        json.dump(p_benign, f, indent=2)
    print("  -> Saved demo_benign_payload.json")

    # 3. Botnet C2 Payload
    p_botnet = {
        "input_type": "state",
        "raw_sequence": df_botnet.values.tolist(),
        "horizons": [1, 3, 6],
        "explain_mode": "full",
        "enrich_mode": "full",
        "description": "NEXUS-Forecast REST API Botnet C2 Payload (CTU-13 Neris Periodic Beaconing)"
    }
    with open(DEMO_DIR / "demo_botnet_payload.json", "w", encoding="utf-8") as f:
        json.dump(p_botnet, f, indent=2)
    print("  -> Saved demo_botnet_payload.json")


def generate_readme():
    print("[5/5] Generating updated data/demo/README.md...")
    readme_content = """# NEXUS-Forecast: Production Demo Telemetry & Traffic Files

This directory contains a comprehensive suite of real-world security telemetry, packet captures, sequence matrices, and API payloads representing various network threat archetypes across **CIC-IDS2017**, **CTU-13**, and **UNSW-NB15**.

All files are directly compatible with the **NEXUS-Forecast Analyst Dashboard** (drag-and-drop file uploader), the offline CLI runner, and the REST API.

---

## Complete Demo Catalog

### 1. CSV Telemetry Files (10 Windows x 22 Canonical Features)
Drag and drop any of these directly into the **Live Inference** tab in the Dashboard, or pass them to the CLI:

| File | Attack Category | Dataset Source | Key Characteristics |
| :--- | :--- | :--- | :--- |
| `demo_attack_telemetry.csv` | **Volumetric DDoS SYN Flood** | CIC-IDS2017 | Extreme packet rate surge, elevated SYN ratio, high IAT variance |
| `demo_benign_telemetry.csv` | **Normal Baseline Traffic** | CIC-IDS2017 | Stable flow rates, balanced bidirectional traffic, zero anomaly |
| `demo_botnet_ctu13.csv` | **Botnet C2 & Beaconing** | CTU-13 (Neris) | Periodic interarrival times, persistent external C&C channels |
| `demo_web_attacks.csv` | **Web Brute Force & SQLi** | CIC-IDS2017 | High connection failure rate, repeated HTTP target probes |
| `demo_infiltration_lateral.csv` | **Infiltration & Lateral Recon** | CIC-IDS2017 | Internal IP port dispersion, expanding destination footprint |
| `demo_unsw_multistage.csv` | **Multi-Stage Kill-Chain** | UNSW-NB15 | Progressive transition across Recon $\\to$ C2 $\\to$ Execution |

---

### 2. Raw Binary Packet Captures (.pcap)
Processed in real time by the pure-Python zero-dependency PCAP parser (`UploadService.parse_pcap_stream`):

| File | Protocol & Type | Target Scenario |
| :--- | :--- | :--- |
| `demo_portscan_traffic.pcap` | TCP SYN / Multi-Port | Horizontal reconnaissance scanning across 20 common service ports |
| `demo_synflood_traffic.pcap` | TCP SYN Flood | High-frequency SYN flood directed at web servers (ports 80 & 443) |
| `demo_dns_amplification.pcap` | UDP DNS Reflection | Heavy UDP port 53 amplification packets with large response payloads |

---

### 3. Multi-Scenario Parquet Files (.parquet)
Pre-windowed canonical sequence collections suitable for batch evaluation and comparative analysis:

| File | Scenarios Included | Description |
| :--- | :--- | :--- |
| `demo_attack_scenarios.parquet` | DDoS, PortScan, Infiltration, Benign | Flagship evaluation dataset across multiple threat categories |
| `demo_ctu13_botnet_scenarios.parquet` | Scenario 01 (Neris), Scenario 03 (RBot), Benign | Real enterprise botnet infections from CTU University |
| `demo_unsw_nb15_scenarios.parquet` | Advanced Fuzzers, Backdoors, Exploits | Complex multi-stage modern attack vectors |
| `example_sequence.parquet` | Canonical Test Sequence | Baseline sequence used for internal integration tests |

---

### 4. REST API Payloads (.json)
Ready-to-use payloads for testing the `POST /api/v1/inference/predict` or `POST /api/inference/run` endpoints:

| File | Scenario | Purpose |
| :--- | :--- | :--- |
| `demo_api_payload.json` | Volumetric Attack | Tests automated threat detection, alerts, and MITRE mapping |
| `demo_benign_payload.json` | Baseline Normal | Confirms low false-alarm rate and benign classification |
| `demo_botnet_payload.json` | Botnet Command & Control | Tests persistence and command-and-control stage attribution |

---

## How to Use These Files

### Option A: Via the Web Dashboard
1. Open the workstation in your browser: `http://localhost:8000`
2. Navigate to the **Live Inference** tab.
3. Drag and drop any `.csv`, `.pcap`, or `.parquet` file from this folder into the upload dropzone.
4. View the real-time GRU forward simulation, multi-horizon trajectories (+30s, +90s, +180s), and integrated gradient attributions.

### Option B: Via Command Line (CLI)
```bash
# Run inference on any CSV file
python -m src.inference.run --input data/demo/demo_botnet_ctu13.csv --explain lightweight

# Run inference on multi-scenario parquet and generate a Markdown report
python -m src.inference.run --input data/demo/demo_attack_scenarios.parquet --format markdown --output outputs/demo_brief.md
```

### Option C: Via cURL / API
```bash
# Upload a PCAP file to the REST API
curl -X POST "http://localhost:8000/api/inference/upload" \\
  -F "file=@data/demo/demo_synflood_traffic.pcap"

# Post a JSON state sequence
curl -X POST "http://localhost:8000/api/inference/run" \\
  -H "Content-Type: application/json" \\
  -d @data/demo/demo_api_payload.json
```
"""
    with open(DEMO_DIR / "README.md", "w", encoding="utf-8") as f:
        f.write(readme_content)
    print("  -> Saved data/demo/README.md")


def main():
    print("=== Generating Expanded NEXUS-Forecast Demo Suite ===")
    samples = generate_parquet_demos()
    df_ddos, df_benign, df_botnet = generate_csv_demos(samples)
    generate_pcap_demos()
    generate_json_payloads(df_ddos, df_benign, df_botnet)
    generate_readme()
    print("=== Demo Suite Generation Finished Successfully ===")


if __name__ == "__main__":
    main()
