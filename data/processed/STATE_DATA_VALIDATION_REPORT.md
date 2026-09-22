# NEXUS-Forecast State Data & Sequence Validation Report

**Generated**: 2026-09-21T16:49:38.508452+00:00  
**Phase**: Phase 12 (Canonical Temporal Network State Construction)  

## 1. Executive Summary

- **Total Generated Network States ($S_t$)**: 23,642 windows
- **Total Multi-Step Forecast Sequences ($X_t \rightarrow Y_{t+K}$)**: 23,290 sequences
- **History Window**: $L = 10$ windows (300 seconds of observed context)
- **Prediction Horizons**: $K \in \{1, 3, 6\}$ (+30s, +90s, +180s into the future)

## 2. Dataset and Scenario Statistics

| Dataset | Scenario ID | Total Flows | Total Windows | Attack Windows | Benign Windows | Sequences | Time Span |
|---|---|---|---|---|---|---|---|
| CIC-IDS2017 | `Friday-WorkingHours-Afternoon-DDos` | 225,745 | 184 | 42 | 142 | 168 | 2017-07-07T03:30:00 $\rightarrow$ 2017-07-07T05:02:30 |
| CIC-IDS2017 | `Friday-WorkingHours-Afternoon-PortScan` | 286,467 | 298 | 54 | 244 | 282 | 2017-07-07T01:00:00 $\rightarrow$ 2017-07-07T03:29:30 |
| CIC-IDS2017 | `Friday-WorkingHours-Morning` | 191,033 | 480 | 325 | 155 | 464 | 2017-07-07T08:59:00 $\rightarrow$ 2017-07-07T12:59:30 |
| CIC-IDS2017 | `Monday-WorkingHours` | 529,918 | 974 | 0 | 974 | 958 | 2017-03-07T01:00:01 $\rightarrow$ 2017-03-07T13:00:31 |
| CIC-IDS2017 | `Thursday-WorkingHours-Afternoon-Infilteration` | 288,602 | 488 | 56 | 432 | 472 | 2017-06-07T01:00:00 $\rightarrow$ 2017-06-07T05:04:30 |
| CIC-IDS2017 | `Thursday-WorkingHours-Morning-WebAttacks` | 170,366 | 480 | 136 | 344 | 464 | 2017-06-07T08:59:00 $\rightarrow$ 2017-06-07T12:59:30 |
| CIC-IDS2017 | `Tuesday-WorkingHours` | 445,909 | 974 | 254 | 720 | 958 | 2017-04-07T01:00:00 $\rightarrow$ 2017-04-07T12:59:30 |
| CIC-IDS2017 | `Wednesday-workingHours` | 692,703 | 1,016 | 172 | 844 | 1,000 | 2017-05-07T01:00:00 $\rightarrow$ 2017-05-07T12:59:30 |
| UNSW-NB15 | `full_capture` | 3,540,241 | 2,920 | 1,641 | 1,279 | 2,904 | 2015-01-22T07:49:41 $\rightarrow$ 2015-02-18T08:30:11 |
| CTU-13 | `scenario_01` | 2,824,636 | 735 | 568 | 167 | 719 | 2011-08-10T09:46:53 $\rightarrow$ 2011-08-10T15:54:53 |
| CTU-13 | `scenario_02` | 1,808,122 | 504 | 408 | 96 | 488 | 2011-08-11T09:49:35 $\rightarrow$ 2011-08-11T14:02:05 |
| CTU-13 | `scenario_03` | 4,710,638 | 8,019 | 1,840 | 6,179 | 8,003 | 2011-08-12T15:24:01 $\rightarrow$ 2011-08-15T10:14:01 |
| CTU-13 | `scenario_04` | 1,121,076 | 509 | 180 | 329 | 493 | 2011-08-15T10:42:52 $\rightarrow$ 2011-08-15T15:11:52 |
| CTU-13 | `scenario_05` | 129,832 | 61 | 42 | 19 | 45 | 2011-08-15T16:43:20 $\rightarrow$ 2011-08-15T17:14:20 |
| CTU-13 | `scenario_06` | 558,919 | 259 | 243 | 16 | 243 | 2011-08-16T10:01:46 $\rightarrow$ 2011-08-16T12:11:46 |
| CTU-13 | `scenario_07` | 114,077 | 43 | 9 | 34 | 27 | 2011-08-16T13:51:24 $\rightarrow$ 2011-08-16T14:13:24 |
| CTU-13 | `scenario_08` | 2,954,230 | 2,337 | 2,185 | 152 | 2,321 | 2011-08-16T14:18:55 $\rightarrow$ 2011-08-17T09:47:55 |
| CTU-13 | `scenario_09` | 2,087,508 | 629 | 365 | 264 | 613 | 2011-08-17T11:34:49 $\rightarrow$ 2011-08-17T17:12:49 |
| CTU-13 | `scenario_10` | 1,309,791 | 577 | 143 | 434 | 561 | 2011-08-18T09:56:29 $\rightarrow$ 2011-08-18T15:05:59 |
| CTU-13 | `scenario_11` | 107,251 | 33 | 11 | 22 | 17 | 2011-08-18T15:39:35 $\rightarrow$ 2011-08-18T15:56:35 |
| CTU-13 | `scenario_12` | 325,471 | 157 | 119 | 38 | 141 | 2011-08-19T10:02:43 $\rightarrow$ 2011-08-19T11:46:13 |
| CTU-13 | `scenario_13` | 1,925,149 | 1,965 | 1,956 | 9 | 1,949 | 2011-08-15T17:13:40 $\rightarrow$ 2011-08-16T09:36:40 |

## 3. Core Acceptance Criteria & Audit Results

| Test # | Validation Check | Expected Standard | Empirical Result | Status |
|---|---|---|---|---|
| **1** | Chronological Ordering | Monotonically increasing timestamps per scenario | Monotonic per scenario | PASS |
| **2** | Duplicate Windows | Zero duplicate (dataset, scenario_id, window_start) | 0 duplicates | PASS |
| **3** | Missing Values in S_t | Exactly 0 nulls in all 20 required state dimensions | 0 nulls | PASS |
| **4** | Infinite Values in S_t | Exactly 0 inf / -inf values | 0 infinite values | PASS |
| **5** | Feature Range Bounds | Non-negative counts, durations, and rates | All counts and rates non-negative | PASS |
| **6** | Label Consistency | Primary stage assigned whenever attack_flag == 1 | Stage non-null for all windows | PASS |
| **7** | Anti-Leakage Audit | t_input <= t_origin < t_target for all sequences | Zero future leakage confirmed | PASS |
| **8** | Temporal Separation | Chronological train (70%) / val (15%) / test (15%) | Strictly partitioned per scenario | PASS |
| **9** | Sequence Continuity | Step size exactly 30s between consecutive windows | Verified 30s rolling step | PASS |
| **10** | Target Semantics | Benign horizon retains BENIGN; stage priority deterministic | Rules applied per TARGET_DEFINITION.md | PASS |

## 4. Anti-Leakage Audit Details

> [!IMPORTANT]
> **Mathematical Proof of Anti-Leakage Guarantee**:
> For every sequence i, the historical input tensor X_i spans indices [i - L + 1, i], ending at prediction_origin = window_end_i.
> Target states and labels Y_{i, K} are sampled strictly at index i + K, where K >= 1.
> Because window_start_{i+1} >= window_end_i, all target information resides strictly in the future relative to the prediction origin.
> Zero test data or validation data was utilized to calculate normalizations or state aggregations.

## 5. Class & Stage Distribution Across Splits

```
      current_attack_flag           future_attack_k1           future_attack_k3           future_attack_k6          
                    count      mean            count      mean            count      mean            count      mean
split                                                                                                               
TEST                 3515  0.762731             3515  0.762447             3515  0.761878             3515  0.758179
TRAIN               16292  0.372821            16292  0.373619            16292  0.374478            16292  0.376197
VAL                  3483  0.547804             3483  0.547804             3483  0.547517             3483  0.546655
```
