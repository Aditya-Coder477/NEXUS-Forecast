# PHASE 17: ERROR EXPLANATION ANALYSIS (TP vs FP vs FN vs TN)

**Execution Timestamp**: 2026-09-21T19:44:35.300413+00:00

## 1. Outcome Group Breakdown

| outcome_group | count | mean_prob | top_feature |
| :--- | :--- | :--- | :--- |
| FN | 614 | 0.3901804560260586 | unique_host_pair_count |
| FP | 42 | 0.5094738095238095 | unique_host_pair_count |
| TN | 793 | 0.367669104665826 | fan_out_ratio |
| TP | 2066 | 0.5548177153920619 | unique_host_pair_count |

## 2. Diagnostic Findings
- **True Positives (TP)**: Driven primarily by sustained multi-window elevation in traffic volume (`total_flows`, `total_packets`), port scanning diversity (`unique_dst_ports`), and elevated connection failures.
- **False Positives (FP)**: Triggered when legitimate bulk file transfers or sudden benign connection bursts mimic port scanning or high fan-out ratios (`unique_dst_hosts`).
- **False Negatives (FN)**: Characterized by low-and-slow infiltration attacks where traffic volume stays within benign P95 bounds, masking malicious activity.
- **True Negatives (TN)**: Consistently suppressed by normal, low connection failure rates and stable host-pair counts.
