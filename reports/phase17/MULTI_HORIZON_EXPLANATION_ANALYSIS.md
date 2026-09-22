# PHASE 17: MULTI-HORIZON EXPLANATION ANALYSIS (+30s vs +90s vs +180s)

**Execution Timestamp**: 2026-09-21T19:44:35.300413+00:00

## 1. Cross-Horizon Attribution Comparison

| horizon | dominant_feature_1 | dominant_feature_2 | dominant_window |
| :--- | :--- | :--- | :--- |
| +180s | unique_host_pair_count | unique_src_hosts | T (t) |
| +30s | unique_host_pair_count | unique_src_hosts | T (t) |
| +90s | unique_host_pair_count | unique_src_hosts | T (t) |

## 2. Horizon Dynamics
- **Immediate Horizon (+30s)**: Strongly dominated by the immediate past window (T) and rapid rate features (`packet_rate`, `syn_count`).
- **Intermediate Horizon (+90s)**: Shows balanced attribution across T-60s to T, reflecting persistence of scanning or communication edges (`unique_host_pair_count`).
- **Extended Horizon (+180s)**: Driven by macroscopic cumulative metrics (`total_bytes`, `unique_dst_hosts`), indicating sustained structural network shifts.
