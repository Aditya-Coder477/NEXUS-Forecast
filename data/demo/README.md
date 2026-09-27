# NEXUS-Forecast: Demo Telemetry & Traffic Files

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
python -m src.inference.run \
    --input data/demo/demo_attack_scenarios.parquet \
    --explain full \
    --enrich full \
    --format markdown \
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
python -m src.inference.run \
    --input data/demo/demo_attack_telemetry.csv \
    --explain lightweight \
    --enrich full \
    --format json
```

### Run Benign Telemetry:
```bash
python -m src.inference.run \
    --input data/demo/demo_benign_telemetry.csv \
    --explain lightweight \
    --enrich full \
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
curl -X POST "http://localhost:8000/api/v1/inference/upload" \
    -F "file=@data/demo/demo_portscan_traffic.pcap" \
    -F "explain_mode=lightweight" \
    -F "enrich_mode=full"
```

---

## 4. REST API Live Payload Testing (`demo_api_payload.json`)

Integrate directly with external SIEMs (Splunk, Elastic SIEM, Microsoft Sentinel):

```bash
curl -X POST "http://localhost:8000/api/v1/inference/predict" \
    -H "Content-Type: application/json" \
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
