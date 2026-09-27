# NEXUS-Forecast: Production Demo Telemetry & Traffic Files

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
| `demo_unsw_multistage.csv` | **Multi-Stage Kill-Chain** | UNSW-NB15 | Progressive transition across Recon $\to$ C2 $\to$ Execution |

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
curl -X POST "http://localhost:8000/api/inference/upload" \
  -F "file=@data/demo/demo_synflood_traffic.pcap"

# Post a JSON state sequence
curl -X POST "http://localhost:8000/api/inference/run" \
  -H "Content-Type: application/json" \
  -d @data/demo/demo_api_payload.json
```
