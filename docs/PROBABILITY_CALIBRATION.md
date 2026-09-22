# Documentation: Probability Calibration & Operating Threshold Selection

## 1. Probability Calibration

Neural networks trained with binary cross-entropy often output uncalibrated probabilities (i.e. predicted probabilities do not equal empirical frequencies).

### 1.1 Platt Scaling Formulation
Platt scaling fits a logistic regression model over the raw model logits $z$:
$$P_{\text{cal}}(y=1 \mid z) = \frac{1}{1 + \exp(-(\alpha \cdot z + \beta))}$$
where parameters $\alpha$ and $\beta$ are learned by minimizing cross-entropy on the **held-out validation partition** (`VAL`).

### 1.2 Evaluation Metrics
- **Brier Score**: Mean squared error between predicted probability $p_i$ and binary label $y_i \in \{0, 1\}$:
  $$\text{Brier} = \frac{1}{N} \sum_{i=1}^N (p_i - y_i)^2$$
- **Expected Calibration Error (ECE)**: Groups predictions into $M=10$ bins and computes the weighted absolute difference between average confidence and empirical accuracy:
  $$\text{ECE} = \sum_{m=1}^M \frac{|B_m|}{N} \left| \text{acc}(B_m) - \text{conf}(B_m) \right|$$

---

## 2. Operating Threshold Selection Policy

1. **Validation-Only Tuning**: Thresholds from $0.10$ to $0.90$ (step $0.05$) are evaluated exclusively on the validation set (`VAL`).
2. **Objective Function**: Select the threshold $\theta^*$ that maximizes the balanced harmonic mean between Recall and Precision, while constraining False Positive Rate:
   $$\theta^* = \arg\max_\theta \left( F_1(\theta) - 0.5 \cdot \text{FPR}(\theta) \right)$$
3. **Freeze on Test**: The selected threshold is stored in `models/world_model/gru/calibration_config.json` and applied exactly once to the test set without post-hoc tuning.
