# PHASE 17 IMPLEMENTATION AUDIT: REPOSITORY ASSETS, ARTIFACT IMMUTABILITY & TRACEABILITY

**Execution Timestamp**: 2026-09-22T01:05:00Z  
**Phase**: Phase 17 (Explainability & Evidence Attribution)  
**Author**: NEXUS-Forecast Pair Programmer  

---

## 1. Frozen Model Artifacts & Baseline Immutability Hashes

To guarantee strict model and configuration immutability (zero retraining, zero parameter changes), the SHA256 cryptographic checksums of all core Phase 15 and Phase 16 model artifacts were calculated prior to the implementation of Phase 17:

| Artifact | File Path | File Size | SHA256 Checksum | Immutability Status |
|:---|:---|:---:|:---|:---:|
| **GRU Model Weights** | `models/world_model/gru/best_model.pt` | 919,925 B | `9f94d0aacff538096d2770e1b4f1509e5b38ae8f78f0cb31b850cb903fa8bc9f` | FROZEN / READ-ONLY |
| **StandardScaler** | `models/world_model/gru/scaler.joblib` | 1,111 B | `9d1e26da627dd0879f2bb640fa762bce14e50ac9f875e9fff8ee6d2a969a2ff2` | FROZEN / READ-ONLY |
| **Platt Calibrator** | `models/world_model/gru/calibration_model.joblib` | 1,694 B | `61b50aa5c47bde70c216714d04b0bf45c831c40e73f23c90214dc5a6f429fda7` | FROZEN / READ-ONLY |
| **Calibration Config** | `models/world_model/gru/calibration_config.json` | 1,441 B | `9139f68474fbc98dd93d53d38cf3bfc6ce5d142e49d8218f5ce893d8877d050b` | FROZEN / READ-ONLY |
| **Model Metadata** | `models/world_model/gru/metadata.json` | 1,045 B | `0dec04495b8f572579001576b39ce3f643f9b7e3487f9b12e534ed008ea160c0` | FROZEN / READ-ONLY |
| **GRU Architecture Config** | `configs/gru_config.yaml` | 892 B | `bc8d4dc6ba2de72d2a6659a5d2ee8e2902f032fbac8a7cf19b51fd05266aaab0` | FROZEN / READ-ONLY |

*Verification Rule*: At the conclusion of Phase 17, these hashes will be re-verified to prove that no models or scalers were overwritten.

---

## 2. Model Architecture & Operational Parameters

- **Architecture Class**: `src.world_model.gru_model.GRUWorldModel`
- **Encoder**: 2-Layer Unidirectional GRU (`input_size=22`, `hidden_size=128`, `num_layers=2`, `dropout=0.2`, `bidirectional=False`)
- **Latent Projection**: LayerNorm(128) + Dropout(0.2)
- **Heads per Horizon** ($K \in \{1, 3, 6\}$):
  - `state_heads`: Linear(128, 64) -> ReLU -> Dropout(0.1) -> Linear(64, 22)
  - `attack_heads`: Linear(128, 32) -> ReLU -> Linear(32, 1) [Raw Logits]
  - `stage_heads`: Linear(128, 64) -> ReLU -> Linear(64, 9) [Raw Multi-class Logits]
- **Operational Threshold**: $\theta^* = 0.45$
- **Calibration Method**: Platt Scaling $\sigma(a \cdot z + b)$ fitted on `VAL` partition:
  - $K=1$ (+30s): $a = 0.1950$, $b = -0.3543$
  - $K=3$ (+90s): $a = 0.1990$, $b = -0.3720$
  - $K=6$ (+180s): $a = 0.2004$, $b = -0.3361$

---

## 3. Canonical 22-Feature Network State Schema

The authoritative 22-dimensional feature schema is loaded directly from `src.world_model.dataset.STATE_FEATURE_NAMES`:

| Index | Feature Name | Description | Units / Scale | Traceability to Flows |
|:---:|:---|:---|:---|:---:|
| 0 | `total_flows` | Count of network flows active in window | Integer count | YES (`count(flow)`) |
| 1 | `unique_src_hosts` | Count of distinct source IP addresses | Integer count | YES (`nunique(src_ip)`) |
| 2 | `unique_dst_hosts` | Count of distinct destination IP addresses | Integer count | YES (`nunique(dst_ip)`) |
| 3 | `unique_dst_ports` | Count of distinct destination ports targeted | Integer count | YES (`nunique(dst_port)`) |
| 4 | `unique_protocols` | Count of distinct transport/network protocols | Integer count | YES (`nunique(protocol)`) |
| 5 | `total_packets` | Aggregated forward + backward packets | Total packets | YES (`sum(pkts_fwd + pkts_bwd)`) |
| 6 | `total_bytes` | Aggregated forward + backward bytes | Total bytes | YES (`sum(bytes_fwd + bytes_bwd)`) |
| 7 | `inbound_bytes` | Total bytes destined inward to local network | Inbound bytes | YES (`sum(bytes)` where `is_inbound=1`) |
| 8 | `outbound_bytes` | Total bytes initiated outward from local network | Outbound bytes | YES (`sum(bytes)` where `is_outbound=1`) |
| 9 | `inbound_outbound_ratio` | Ratio of inbound to outbound traffic volume | Dimensionless ratio | YES (`(in_bytes+1)/(out_bytes+1)`) |
| 10 | `mean_flow_duration` | Average duration of flows terminating in window | Seconds / ms | YES (`mean(duration)`) |
| 11 | `mean_packet_rate` | Average packets per second across flows | Packets / sec | YES (`mean(packet_rate)`) |
| 12 | `mean_byte_rate` | Average bytes per second across flows | Bytes / sec | YES (`mean(byte_rate)`) |
| 13 | `mean_iat` | Average inter-arrival time between packets | Seconds (or -1.0 sentinel) | PARTIAL (`mean(valid iat_mean)`) |
| 14 | `std_iat` | Standard deviation of inter-arrival times | Seconds (or -1.0 sentinel) | PARTIAL (`mean(valid iat_std)`) |
| 15 | `syn_count` | Aggregated TCP SYN flags observed | Integer count | YES (`sum(tcp_syn)`) |
| 16 | `ack_count` | Aggregated TCP ACK flags observed | Integer count | YES (`sum(tcp_ack)`) |
| 17 | `rst_count` | Aggregated TCP RST flags observed | Integer count | YES (`sum(tcp_rst)`) |
| 18 | `fin_count` | Aggregated TCP FIN flags observed | Integer count | YES (`sum(tcp_fin)`) |
| 19 | `connection_failure_rate` | Ratio of aborted/reset to initiated sessions | Ratio: `(rst+1)/(syn+1)` | YES (`(rst_count+1)/(syn_count+1)`) |
| 20 | `unique_host_pair_count` | Count of distinct (src_ip, dst_ip) edges | Distinct pairs count | YES (`nunique((src_ip, dst_ip))`) |
| 21 | `fan_out_ratio` | Destination hosts targeted per source host | Ratio: `dst_hosts / src_hosts` | YES (`unique_dst / unique_src`) |

---

## 4. Attack Stage Taxonomy

The 9 canonical macroscopic stages defined in `src.world_model.dataset.STAGE_VOCABULARY`:
0. `BENIGN`
1. `RECONNAISSANCE`
2. `INITIAL_ACCESS`
3. `EXECUTION`
4. `DISCOVERY`
5. `CREDENTIAL_ACCESS`
6. `LATERAL_MOVEMENT`
7. `COMMAND_AND_CONTROL`
8. `EXFILTRATION`

---

## 5. Temporal Sequence Datasets & Partitions

The sequence parquets (`data/processed/forecast_sequences/`) contain chronological sequences with $L=10$ historical windows ($S_{t-9} \dots S_t$) and multi-horizon targets:
- `cic_ids2017_sequences.parquet`: 4,818 sequences (Train: 3,372 | Val: 723 | Test: 723)
- `unsw_nb15_sequences.parquet`: 2,907 sequences (Train: 2,033 | Val: 437 | Test: 437)
- `ctu13_sequences.parquet`: 15,565 sequences (Train: 10,855 | Val: 2,355 | Test: 2,355)
- **Pooled Total**: 23,290 sequences (Train: 16,260 | Val: 3,515 | Test: 3,515)

Anti-leakage Guarantee:
- All baseline reference statistics (median, mean, std, P95, IQR) will be calculated **strictly from the `TRAIN` split ($N=16,260$)**.
- Zero test data or future horizons will be used to construct reference baselines.

---

## 6. Raw & Processed Flow Data Sources

The underlying network flow datasets are organized as follows:
- **CIC-IDS2017**: CSV flows in `data/CIC-IDS2017/CSV/GeneratedLabelledFlows/TrafficLabelling/*.csv`
- **UNSW-NB15**: CSV flows in `data/UNSW-NB15/CSV/*.csv`
- **CTU-13**: Bidirectional netflows in `data/CTU-13-Dataset/`
- **State Window Cache**: `data/processed/network_states/*.parquet` contains the exact 60s windows (`window_start`, `window_end`, `scenario_id`) allowing immediate correlation between sequences and canonical windows.

---

## 7. MITRE ATT&CK & CAPEC Knowledge Layer

Located in `data/knowledge/mitre_attack/processed/`:
- `attack_stage_mapping.json`: Mapping between ATT&CK techniques and NEXUS stages. Includes 19 techniques marked `REVIEW_REQUIRED`.
- `nexus_forecast_attack_knowledge.json`: Detailed descriptions, tactics, and mitigations.
- *Strict Boundary Rule*: MITRE context is strictly informational and will never be presented as physical proof that a specific technique occurred. `REVIEW_REQUIRED` technique mappings will remain preserved.
