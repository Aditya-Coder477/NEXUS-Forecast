# Documentation: Forecasted Infiltration Likelihood Definition

## 1. Context & Purpose
In **NEXUS-Forecast**, the central predictive output is the **Forecasted Infiltration Likelihood** ($\mathcal{L}_{\text{infil}}$). 

To preserve scientific rigor and prevent misleading claims, this document establishes the formal operational and mathematical definition of this metric, explicitly specifying what it means and what it does not mean.

---

## 2. Operational Definition

Given an observed historical sequence of network states $X_t = [S_{t-9}, \dots, S_t]$ terminating at prediction origin $t$:
1. The temporal World Model outputs a forecasted binary attack probability:
   $$\hat{P}_{\text{raw}}(t+K) = \sigma(z_{\text{attack}, K})$$
2. This raw probability is calibrated on held-out validation data using Platt scaling (sigmoid regression):
   $$\hat{P}_{\text{cal}}(t+K) = \frac{1}{1 + \exp(-(\alpha_K \cdot z_{\text{attack}, K} + \beta_K))}$$
3. For Phase 16, the **Forecasted Infiltration Likelihood** at horizon $K$ is defined directly as this calibrated attack probability:
   $$\mathcal{L}_{\text{infil}}(t+K) = \hat{P}_{\text{cal}}(t+K)$$

---

## 3. What Forecasted Infiltration Likelihood Means
- It is a **model-derived statistical forecast** representing the likelihood that network traffic in the future time interval $[t+K\cdot 30\text{s}, t+K\cdot 30\text{s} + 60\text{s})$ will exhibit anomalous attack patterns matching known adversarial tactics.
- It reflects the temporal trajectory and state momentum of the monitored network environment.
- It is calibrated against empirical frequencies on held-out validation sequences.

---

## 4. What Forecasted Infiltration Likelihood Does NOT Mean
- **NOT a Guaranteed Probability of Compromise**: It does not certify that a target host will be successfully exploited or that defenses have been breached.
- **NOT an Attacker Intent Oracle**: It models network traffic characteristics, not the cognitive decisions of a human adversary.
- **NOT an Arbitrary Heuristic Score**: It is strictly derived from trained neural heads and validation calibration, rather than ad-hoc rule-based point systems.
