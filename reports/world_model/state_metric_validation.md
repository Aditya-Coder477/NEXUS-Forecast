# Scientific Investigation & Validation Report: Network State Forecasting Metrics ($R^2$ vs MAE/RMSE)

**Generated**: 2026-09-21T18:18:00Z  
**Phase**: Phase 16 Metric Integrity Audit  

---

## 1. Executive Summary

During Phase 14 (LSTM) and Phase 15 (GRU) evaluation, an apparent anomaly was observed:
- **Overall Pooled Model $R^2$** was consistent and healthy at **$R^2 \approx 0.58 - 0.61$**.
- **Dataset-Specific $R^2$** on subsets (notably UNSW-NB15 and CTU-13) produced extreme negative values (e.g. $-10^{27}$ or $-10^6$).

This report provides the mathematical proof and empirical audit explaining this behavior. In short:
**Certain canonical features have exact zero or near-zero variance within individual dataset test splits, causing the $R^2$ denominator ($\sum (y_i - \bar{y})^2$) to collapse to zero.**

Consequently, **Mean Absolute Error (MAE)** and **Root Mean Squared Error (RMSE)** are established as the robust, primary scientific metrics for continuous network state forecasting.

---

## 2. Mathematical Diagnosis of $R^2$ Collapse

The coefficient of determination $R^2$ is defined as:
$$R^2 = 1 - \frac{\text{SS}_{\text{res}}}{\text{SS}_{\text{tot}}} = 1 - \frac{\sum_{i=1}^N (y_i - \hat{y}_i)^2}{\sum_{i=1}^N (y_i - \bar{y})^2}$$

When evaluated on a dataset partition where a feature $j$ is constant:
$$y_{i, j} = c \quad \forall i \implies \bar{y}_j = c \implies \text{SS}_{\text{tot}, j} = \sum_{i=1}^N (c - c)^2 = 0$$

If the regression model produces any minor residual $\epsilon_i = \hat{y}_i - c \ne 0$ (e.g. $\epsilon = 0.001$), then:
$$R_j^2 = 1 - \frac{\sum \epsilon_i^2}{0} \rightarrow -\infty$$

When calculating the mean $R^2$ across all 22 features, a single feature with $\text{SS}_{\text{tot}} \approx 0$ completely distorts the macro-averaged $R^2$ to arbitrary negative orders of magnitude.

---

## 3. Empirical Feature Variance Audit Across Test Splits

An automated variance scan across all 22 target features in the test splits revealed:

### 1. CTU-13 (2,355 test sequences)
- `target_S_k_mean_iat`: **Variance = 0.00000000**
- `target_S_k_std_iat`: **Variance = 0.00000000**
- *Reason*: Inter-Arrival Time (IAT) is structurally unavailable in Argus Binetflow files and is intentionally set to the sentinel value `-1.0` (as verified in Phase 12).
- When standardized using the pooled scaler, this constant sentinel has $\text{SS}_{\text{tot}} = 0$, producing division by zero in $R^2$.

### 2. UNSW-NB15 (437 test sequences)
- `target_S_k_unique_protocols`: **Variance = 0.00000000**
- `target_S_k_connection_failure_rate`: **Variance = 0.00000095**
- *Reason*: The test partition of UNSW-NB15 captures a high-intensity attack phase where every single window contains identical protocol cardinality.

### 3. Pooled Overall Test Set (3,515 test sequences)
- Combining CIC-IDS2017 (with varied IATs and protocols) with UNSW-NB15 and CTU-13 restores variance to every single feature ($\text{SS}_{\text{tot}} > 0$).
- Hence, the Overall $R^2$ evaluates stably at **$0.58 - 0.61$**, confirming strong predictive explanation of real variance across the network domains.

---

## 4. Corrected Scientific Methodology for Phase 16

1. **Primary State Metrics**:
   - **Mean Absolute Error (MAE)**: Measures average absolute deviation in standardized feature units. Invariant to denominator collapse.
   - **Root Mean Squared Error (RMSE)**: Penalizes large state trajectory outliers. Invariant to denominator collapse.
2. **Conditional $R^2$ Reporting**:
   - $R^2$ is only reported on features where $\text{Var}(y) > 10^{-4}$.
   - Macro $R^2$ is reported on the pooled multi-domain test set where all 22 features possess non-zero variance.
