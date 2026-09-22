# NEXUS-Forecast Phase 15: GRU-Based Temporal World Model Report

**Generated**: 2026-09-21T17:27:42.410591+00:00  
**Status**: COMPLETE (Phase 15 GRU Gate Passed)  

## 1. Objective & Relationship to LSTM

Phase 15 introduces the **GRU (Gated Recurrent Unit) World Model** as a rigorous, controlled architectural comparison against the LSTM World Model (Phase 14). Both models were trained and evaluated on the identical Phase 12 temporal state sequences, using the exact same data partitions, random seed (42), sequence length ($L=10$), feature scaling, optimizer parameters, loss weights, and multi-task prediction heads ($S_{t+K}$, $P(\text{attack}_{t+K})$, and attack stage).

## 2. Model Architecture & Computational Complexity

- **Recurrent Backbone**: 2-Layer Unidirectional GRU (`hidden_size=128`, `dropout=0.2`, `bidirectional=False`)
- **Total Parameters**: **225,760** (compared to 278,240 for LSTM, a **18.86% reduction in total parameters** and **25.0% reduction in recurrent parameters**)
- **Model Disk Footprint**: **898.4 KB** (vs 1,103.5 KB for LSTM)
- **Training Time**: **118.4s** across 12 epochs (**9.87s/epoch**)
- **Inference Latency**: **0.0489 ms/sample** on CPU
- **Best Epoch**: Epoch 5 with Validation Loss 2.1120

## 3. Binary Attack Forecasting Performance

| Dataset | Horizon | Attack F1 | Precision | Recall | False Positive Rate (FPR) | Accuracy |
|---|---:|---:|---:|---:|---:|---:|
| **CIC-IDS2017** | +30s | **0.0226** | 0.0157 | 0.0400 | **29.01%** (0.2901) | 0.6404 |
| **CIC-IDS2017** | +90s | **0.0350** | 0.0237 | 0.0667 | **31.79%** (0.3179) | 0.6183 |
| **CIC-IDS2017** | +180s | **0.0361** | 0.0250 | 0.0649 | **30.19%** (0.3019) | 0.6307 |
| **UNSW-NB15** | +30s | **0.9802** | 0.9767 | 0.9836 | **100.0%** (1.0000) | 0.9611 |
| **UNSW-NB15** | +90s | **0.9814** | 0.9768 | 0.9859 | **100.0%** (1.0000) | 0.9634 |
| **UNSW-NB15** | +180s | **0.9802** | 0.9767 | 0.9836 | **100.0%** (1.0000) | 0.9611 |
| **CTU-13** | +30s | **0.9041** | 0.9189 | 0.8898 | **96.61%** (0.9661) | 0.8255 |
| **CTU-13** | +90s | **0.9168** | 0.9251 | 0.9085 | **89.39%** (0.8939) | 0.8476 |
| **CTU-13** | +180s | **0.8996** | 0.9169 | 0.8829 | **89.18%** (0.8918) | 0.8191 |
| **Overall** | +30s | **0.8728** | 0.8648 | 0.8810 | **44.19%** (0.4419) | 0.8043 |
| **Overall** | +90s | **0.8807** | 0.8647 | 0.8973 | **44.92%** (0.4492) | 0.8148 |
| **Overall** | +180s | **0.8679** | 0.8606 | 0.8754 | **44.47%** (0.4447) | 0.7980 |

## 4. Future Network State Forecasting Performance (Regression)

| Dataset | Horizon | State MAE | State RMSE | State R² |
|---|---:|---:|---:|---:|
| **CIC-IDS2017** | +30s | **0.2350** | 0.5732 | -79945972046327.6875 |
| **CIC-IDS2017** | +90s | **0.2366** | 0.5762 | -57757438279526.0312 |
| **CIC-IDS2017** | +180s | **0.2469** | 0.5890 | -14938923883351.8066 |
| **UNSW-NB15** | +30s | **0.1438** | 0.3486 | -10071872471306943170686746624.0000 |
| **UNSW-NB15** | +90s | **0.1478** | 0.3583 | -16286015838602618175355879424.0000 |
| **UNSW-NB15** | +180s | **0.1439** | 0.3633 | -6295939671736080234188898304.0000 |
| **CTU-13** | +30s | **0.1898** | 0.6428 | -1050174.7212 |
| **CTU-13** | +90s | **0.1923** | 0.6587 | -768047.5164 |
| **CTU-13** | +180s | **0.1960** | 0.6915 | -820106.6731 |
| **Overall** | +30s | **0.1934** | 0.5996 | 0.6056 |
| **Overall** | +90s | **0.1959** | 0.6123 | 0.5971 |
| **Overall** | +180s | **0.2000** | 0.6389 | 0.5862 |

## 5. Future Attack Stage Forecasting Performance

| Dataset | Horizon | Stage Accuracy | Stage Macro F1 | Stage Weighted F1 |
|---|---:|---:|---:|---:|
| **CIC-IDS2017** | +30s | **0.8022** | 0.2226 | 0.7979 |
| **CIC-IDS2017** | +90s | **0.8921** | 0.2357 | 0.8452 |
| **CIC-IDS2017** | +180s | **0.8893** | 0.2354 | 0.8412 |
| **UNSW-NB15** | +30s | **0.4256** | 0.1361 | 0.3666 |
| **UNSW-NB15** | +90s | **0.4577** | 0.1155 | 0.3319 |
| **UNSW-NB15** | +180s | **0.4645** | 0.1211 | 0.3346 |
| **CTU-13** | +30s | **0.8042** | 0.6173 | 0.8446 |
| **CTU-13** | +90s | **0.8391** | 0.6532 | 0.8685 |
| **CTU-13** | +180s | **0.7728** | 0.5374 | 0.8130 |
| **Overall** | +30s | **0.7568** | 0.3031 | 0.7685 |
| **Overall** | +90s | **0.8026** | 0.3224 | 0.8055 |
| **Overall** | +180s | **0.7585** | 0.3079 | 0.7625 |

## 6. Autoregressive Rollout vs Direct Horizon Forecasting

| Horizon | Direct Head MAE | Autoregressive Rollout MAE | Error Compounding Delta |
|---:|---:|---:|---:|
| **+30s** | 0.2082 | 0.2082 | **+0.0000** |
| **+90s** | 0.2229 | 0.2300 | **+0.0071** |
| **+180s** | 0.2091 | 0.2302 | **+0.0211** |

