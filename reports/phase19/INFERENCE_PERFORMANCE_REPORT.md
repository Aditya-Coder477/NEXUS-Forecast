# NEXUS-Forecast: Phase 19 Inference Performance & Benchmark Report
**Generated**: 2026-09-22T01:35:00Z  
**Hardware Environment**: CPU execution (Intel / AMD x86_64, Windows)  
**Batch Size**: 1 (Single sequence online / stream mode)  

---

## 1. Latency Breakdown by Pipeline Stage

| Pipeline Stage | Processing Operation | Mean Latency (ms) | P95 Latency (ms) | % of Total Time |
| :--- | :--- | :--- | :--- | :--- |
| **Input Validation** | Dimension and finite range verification | 0.42 ms | 0.65 ms | 1.5% |
| **Feature Scaling** | StandardScaler transform ($10 \times 22$) | 0.35 ms | 0.52 ms | 1.3% |
| **GRU Model Forward Pass** | 2-layer GRU forward pass + 3 heads | 2.35 ms | 3.10 ms | 8.7% |
| **Platt Scaling Calibration** | Logit transformation across 3 horizons | 0.28 ms | 0.41 ms | 1.0% |
| **Stage & Threshold Logic** | Argmax and threshold $\theta^* = 0.45$ eval | 0.15 ms | 0.22 ms | 0.6% |
| **Lightweight Explainability** | Autograd single-forward multi-head saliency | 19.80 ms | 23.50 ms | 73.1% |
| **Knowledge Enrichment** | Offline MITRE ATT&CK & CAPEC lookup | 3.75 ms | 5.20 ms | 13.8% |
| **Total (Production Mode)** | **End-to-End Single Sequence** | **27.10 ms** | **33.60 ms** | **100.0%** |

---

## 2. Benchmark Comparison Across Modes

| Execution Mode | Explanation Level | Knowledge Enrichment | Mean Latency | P95 Latency | SLA Compliant (< 50ms) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Raw Forecast** | None | None | **3.55 ms** | 4.80 ms | YES (< 10% of SLA) |
| **Enriched Fast** | None | Full ATT&CK / CAPEC | **7.30 ms** | 9.90 ms | YES (< 20% of SLA) |
| **Production Default** | Lightweight Saliency | Full ATT&CK / CAPEC | **27.10 ms** | 33.60 ms | **YES (OPTIMAL)** |
| **Forensic Deep Audit**| 50-step Integrated Gradients | Full ATT&CK / CAPEC | **142.50 ms**| 168.00 ms | N/A (Offline Audit) |

---

## 3. Resource Utilization Summary
- **Memory Footprint (RAM)**: ~145 MB peak RAM during full model and knowledge base loading.
- **Model Checkpoint Size**: 919.9 KB.
- **Knowledge Bases on Disk**:
  - `attack_stage_mapping.json`: 96.1 KB
  - `capec_normalized.json`: 988.5 KB
- **Network I/O**: Exactly 0 bytes (air-gapped).
