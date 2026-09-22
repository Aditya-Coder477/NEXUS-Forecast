# NEXUS-Forecast Target Definition & Ground-Truth Rules

This document establishes the exact mathematical, logical, and algorithmic definitions for all window-level ground truth labels and multi-step forecasting targets in **NEXUS-Forecast**.

---

## 1. Window-Level Attack Ground Truth

For each time window $W_t = [t, t + \Delta t)$:

### 1.1 `window_attack_flag`
$$\text{window\_attack\_flag} = \begin{cases} 1 & \text{if } \sum_{i \in W_t} \mathbb{I}(\text{flow}_i \text{ is attack}) > 0 \\ 0 & \text{otherwise} \end{cases}$$

### 1.2 `window_attack_ratio`
$$\text{window\_attack\_ratio} = \frac{\sum_{i \in W_t} \mathbb{I}(\text{flow}_i \text{ is attack})}{|W_t|}$$
where $|W_t|$ is the total number of flows in the window.

### 1.3 `primary_attack_type`
Deterministic assignment rule:
1. If $\text{window\_attack\_flag} = 0$, `primary_attack_type` = `"BENIGN"`.
2. If multiple distinct attack types occur within $W_t$:
   - Select the attack type with the **highest flow count** in $W_t$.
   - If tied, select using **lexicographical alphabetical order** (e.g. `"DDoS"` precedes `"PortScan"`).
   - This prevents row-order non-determinism.

### 1.4 `primary_attack_stage`
Deterministic assignment rule:
1. If $\text{window\_attack\_flag} = 0$, `primary_attack_stage` = `"BENIGN"`.
2. If multiple attack stages co-occur within $W_t$, select using the strict **adversarial progression priority hierarchy**:
   $$\text{EXFILTRATION} > \text{COMMAND\_AND\_CONTROL} > \text{LATERAL\_MOVEMENT} > \text{CREDENTIAL\_ACCESS} > \text{DISCOVERY} > \text{EXECUTION} > \text{INITIAL\_ACCESS} > \text{RECONNAISSANCE} > \text{BENIGN}$$
   *Rationale*: The most advanced compromise stage present in a window dictates the urgency and risk posture for defense forecasting.

---

## 2. Multi-Step Forecast Targets ($K \in \{1, 3, 6\}$)

Given a sequence of historical state vectors $X_t = [S_{t-L+1}, \dots, S_t]$ terminating at prediction origin $t$:

### 2.1 Future State Vectors ($S_{t+K}$)
- $Y_{\text{state}, t+1} = S_{t+1}$ (Horizon +30s)
- $Y_{\text{state}, t+3} = S_{t+3}$ (Horizon +90s)
- $Y_{\text{state}, t+6} = S_{t+6}$ (Horizon +180s)

### 2.2 Future Binary Attack Indicators (`future_attack_k`)
- `future_attack_k1`: Binary indicator $\in \{0, 1\}$ of whether window $t+1$ is under attack.
- `future_attack_k3`: Binary indicator $\in \{0, 1\}$ of whether window $t+3$ is under attack.
- `future_attack_k6`: Binary indicator $\in \{0, 1\}$ of whether window $t+6$ is under attack.

### 2.3 Future Attack Stage (`future_stage_k`)
- Definition: The canonical NEXUS stage observed at the exact future window $t+K$.
- **Strict Benign Preservation Rule**: If window $t+K$ is benign, `future_stage_k` **MUST be recorded as `"BENIGN"`**.
- **No Forward Peeking**: The pipeline does NOT search past window $t+K$ to replace a benign horizon with a future attack. This guarantees that the forecasting target rigorously evaluates:
  1. *Will the network be under attack at horizon $K$?*
  2. *If so, what attack stage is observed at horizon $K$?*

### 2.4 `time_to_next_attack_seconds`
- Definition: The elapsed time in seconds from prediction origin $t$ until the start of the next attack-bearing window within the observation horizon:
  $$\tau_{\text{next}} = \min \{ \text{window\_start}_{t+j} - \text{window\_end}_t \mid j \ge 1 \land \text{window\_attack\_flag}_{t+j} = 1 \}$$
- **Sentinel Policy**: If no attack occurs within the forward forecast observation horizon, `time_to_next_attack_seconds` is recorded as `-1.0` (sentinel indicating no imminent attack).
- **Anti-Leakage Restriction**: This metric is strictly a future target and must NEVER be exposed as an input feature in $S_t$ or $X_t$.
