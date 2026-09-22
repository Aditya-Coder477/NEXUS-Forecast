# PHASE 17 FINAL REPORT: EXPLAINABILITY & EVIDENCE ATTRIBUTION

**Execution Timestamp**: 2026-09-21T19:44:35.300413+00:00
**Status**: COMPLETE
**Target Architecture**: Frozen 2-Layer Unidirectional GRU World Model (225,760 Parameters)
**Operational Threshold**: theta* = 0.45

## 1. Executive Summary

Phase 17 equips the NEXUS-Forecast system with an end-to-end explainability and evidence attribution layer.
- **Top Globally Influential Features**: `unique_host_pair_count`, `unique_src_hosts`, `mean_packet_rate`.
- **Completeness Pass Rate**: 77.23% across evaluation sequences.
- **Immutability Status**: Pre- and post-execution checksums match exactly (zero model drift).

## 2. Global Feature Importance Table

| feature | mean_signed_attribution | mean_absolute_attribution | median_absolute_attribution | top5_frequency | overall_direction | normalized_importance |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| unique_host_pair_count | 2.067017 | 2.089828 | 2.440876 | 0.6723 | attack_supporting | 0.178983 |
| unique_src_hosts | 1.20164 | 1.35468 | 1.279724 | 0.6669 | attack_supporting | 0.116022 |
| mean_packet_rate | 0.824333 | 1.314102 | 1.220213 | 0.8586 | attack_supporting | 0.112546 |
| fan_out_ratio | 0.601442 | 0.974091 | 0.456303 | 0.3784 | attack_supporting | 0.083426 |
| mean_flow_duration | -0.47176 | 0.79301 | 0.708437 | 0.4529 | attack_suppressing | 0.067917 |
| syn_count | 0.685951 | 0.694052 | 0.076921 | 0.1243 | attack_supporting | 0.059442 |
| ack_count | -0.68635 | 0.68697 | 0.003172 | 0.1243 | attack_suppressing | 0.058836 |
| unique_dst_ports | 0.581935 | 0.593885 | 0.267995 | 0.2461 | attack_supporting | 0.050863 |
| unique_protocols | -0.010959 | 0.472946 | 0.257128 | 0.2384 | attack_suppressing | 0.040505 |
| mean_byte_rate | -0.233679 | 0.468592 | 0.193047 | 0.2395 | attack_suppressing | 0.040133 |

## 3. Temporal Attribution Progression

| timestep_index | relative_position | mean_signed_attribution | mean_absolute_attribution | median_absolute_attribution | dominant_direction | normalized_importance |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 0 | T-270s (t-9) | 0.425671 | 0.461167 | 0.385588 | attack_supporting | 0.097169 |
| 1 | T-240s (t-8) | 0.459036 | 0.490987 | 0.421422 | attack_supporting | 0.103452 |
| 2 | T-210s (t-7) | 0.4889 | 0.520476 | 0.459643 | attack_supporting | 0.109666 |
| 3 | T-180s (t-6) | 0.509425 | 0.540609 | 0.487154 | attack_supporting | 0.113908 |
| 4 | T-150s (t-5) | 0.51606 | 0.548072 | 0.508468 | attack_supporting | 0.11548 |
| 5 | T-120s (t-4) | 0.509753 | 0.540022 | 0.516358 | attack_supporting | 0.113784 |
| 6 | T-90s (t-3) | 0.488525 | 0.513566 | 0.515306 | attack_supporting | 0.10821 |
| 7 | T-60s (t-2) | 0.447695 | 0.466762 | 0.466833 | attack_supporting | 0.098348 |
| 8 | T-30s (t-1) | 0.38039 | 0.393219 | 0.385291 | attack_supporting | 0.082852 |
| 9 | T (t) | 0.264628 | 0.271145 | 0.244021 | attack_supporting | 0.057131 |

## 4. Representative SOC Narrative

```text
============================================================
NEXUS-FORECAST — FORECAST EXPLANATION REPORT
============================================================
Dataset:            CIC-IDS2017
Scenario:           Friday-WorkingHours-Afternoon-DDos
Prediction Origin:  2017-07-07T04:46:30
Forecast Horizon:   +30 seconds
Attack Probability: 0.3207 (Calibrated)
Decision Threshold: 0.45
Forecast Decision:  BENIGN_FORECAST
Predicted Stage:    BENIGN (Confidence: 93.19%)
------------------------------------------------------------
WHY? — TOP CONTRIBUTING NETWORK-STATE FEATURES
------------------------------------------------------------
1. fan_out_ratio
   Attribution:  +2.9323 (attack_supporting, relative importance: 37.0%)
2. mean_packet_rate
   Attribution:  -1.5374 (attack_suppressing, relative importance: 19.4%)
3. std_iat
   Attribution:  -1.2992 (attack_suppressing, relative importance: 16.4%)
4. connection_failure_rate
   Attribution:  +1.1344 (attack_supporting, relative importance: 14.3%)
------------------------------------------------------------
WHEN? — MOST INFLUENTIAL HISTORICAL WINDOWS
------------------------------------------------------------
1. T-270s (t-9) | Attribution: +0.1388 (attack_supporting)
2. T-240s (t-8) | Attribution: +0.1483 (attack_supporting)
3. T-210s (t-7) | Attribution: +0.1613 (attack_supporting)
------------------------------------------------------------
WHAT EVIDENCE? — OBSERVED NETWORK BEHAVIOR & DEVIATIONS
------------------------------------------------------------
• Observation in category [HOST_DIVERSITY]: Feature 'fan_out_ratio' was observed at 1.8333 (elevated, baseline median: 0.8552, IQR deviation: 2.31 (P95 exceeded)). Attribution direction: attack_supporting.
• Observation in category [TRAFFIC_VOLUME]: Feature 'mean_packet_rate' was observed at 10,747.3753 (elevated, baseline median: 5,414.1894, IQR deviation: 2.67 (P95 exceeded)). Attribution direction: attack_suppressing.
• Observation in category [CONNECTION_BEHAVIOR]: Feature 'std_iat' was observed at 756,198.1358 (elevated, baseline median: -1.0, IQR deviation: 37.54). Attribution direction: attack_suppressing.
------------------------------------------------------------
HOW SENSITIVE? — MODEL SENSITIVITY UNDER PERTURBATION
------------------------------------------------------------
• Feature: fan_out_ratio
  Calibrated Probability shift when set to benign baseline: 0.3207 -> 0.2688 (Delta: -0.0519)
• Feature: mean_packet_rate
  Calibrated Probability shift when set to benign baseline: 0.3207 -> 0.4322 (Delta: +0.1115)
• Feature: std_iat
  Calibrated Probability shift when set to benign baseline: 0.3207 -> 0.3838 (Delta: +0.0632)
------------------------------------------------------------
ANALYST INTERPRETATION & LIMITATIONS
------------------------------------------------------------
The forecast is driven by specific multi-window deviations from benign baseline traffic.
This explanation describes model attribution and supporting network observations.
It does not establish attacker intent, physical proof, or causal certainty.
============================================================
```
