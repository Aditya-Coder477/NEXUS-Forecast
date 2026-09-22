# Corrected Baseline Evaluation Report: Phase 13 Logistic Regression

**Generated**: 2026-09-21T18:15:00Z  
**Phase**: Phase 13/16 Verification & Correction Gate  

---

## 1. Context and Audit Findings

In Phase 13, two distinct evaluation protocols were executed for Logistic Regression:
1. **Dataset-Specific Models**: Three independent Logistic Regression models trained and evaluated separately on **CIC-IDS2017**, **UNSW-NB15**, and **CTU-13**.
2. **Pooled Master Model**: A single unified Logistic Regression model trained on the combined training sets of all three datasets and evaluated on the combined test set.

In the original `reports/baseline/logistic_regression_results.csv`, the row labeled `Overall` reported the metrics from the **Pooled Master Model**. Consequently, the confusion matrix elements for `Overall` did not equal the direct sum of the three dataset-specific models, because a single unified hyperplane separates the joint space differently than three domain-specific hyperplanes.

To provide 100% scientific transparency, this report and associated artifacts explicitly present **both**:
- **Dataset-Specific Summed Evaluation** (aggregating the test confusion matrices of the 3 independent models).
- **Pooled Master Model Evaluation** (the unified model trained across all domains).

---

## 2. Head-to-Head Numerical Breakdown

### Horizon $K=1$ (+30s nominal delay)
- **CIC-IDS2017 Model**: TN=445, FP=203, FN=69, TP=6 (F1=0.0423, Prec=0.0287, Rec=0.0800, FPR=31.33%)
- **UNSW-NB15 Model**: TN=1, FP=9, FN=0, TP=427 (F1=0.9896, Prec=0.9794, Rec=1.0000, FPR=90.00%)
- **CTU-13 Model**: TN=136, FP=41, FN=376, TP=1,802 (F1=0.8963, Prec=0.9778, Rec=0.8274, FPR=23.16%)
- **SUM OF INDEPENDENT DATASET MODELS**:
  $$\text{TN} = 445 + 1 + 136 = \mathbf{582}, \quad \text{FP} = 203 + 9 + 41 = \mathbf{253}$$
  $$\text{FN} = 69 + 0 + 376 = \mathbf{445}, \quad \text{TP} = 6 + 427 + 1,802 = \mathbf{2,235}$$
  - $\text{Total Test Windows} = 582 + 253 + 445 + 2,235 = \mathbf{3,515}$
  - $\text{Attack Precision} = \frac{2235}{2235 + 253} = \mathbf{0.8983}$
  - $\text{Attack Recall} = \frac{2235}{2235 + 445} = \mathbf{0.8340}$
  - $\text{Attack F1} = 2 \times \frac{0.8983 \times 0.8340}{0.8983 + 0.8340} = \mathbf{0.8649}$
  - $\text{False Positive Rate (FPR)} = \frac{253}{253 + 582} = \mathbf{30.30\%}$ (0.3030)
- **POOLED MASTER MODEL**:
  - $\text{TN}=791, \text{FP}=44, \text{FN}=638, \text{TP}=2,042$
  - $\text{F1} = \mathbf{0.8569}, \text{Prec} = \mathbf{0.9789}, \text{Rec} = \mathbf{0.7619}, \text{FPR} = \mathbf{5.27\%}$

---

### Horizon $K=3$ (+90s nominal delay)
- **CIC-IDS2017 Model**: TN=443, FP=205, FN=71, TP=4
- **UNSW-NB15 Model**: TN=0, FP=10, FN=1, TP=426
- **CTU-13 Model**: TN=134, FP=45, FN=391, TP=1,785
- **SUM OF INDEPENDENT DATASET MODELS**:
  $$\text{TN} = \mathbf{577}, \quad \text{FP} = \mathbf{260}, \quad \text{FN} = \mathbf{463}, \quad \text{TP} = \mathbf{2,215}$$
  - $\text{Attack Precision} = \mathbf{0.8949}, \text{Attack Recall} = \mathbf{0.8271}, \text{Attack F1} = \mathbf{0.8597}, \text{FPR} = \mathbf{31.06\%}$
- **POOLED MASTER MODEL**:
  - $\text{TN}=788, \text{FP}=49, \text{FN}=646, \text{TP}=2,032$
  - $\text{Attack F1} = \mathbf{0.8540}, \text{Prec} = \mathbf{0.9765}, \text{Rec} = \mathbf{0.7588}, \text{FPR} = \mathbf{5.85\%}$

---

### Horizon $K=6$ (+180s nominal delay)
- **CIC-IDS2017 Model**: TN=446, FP=200, FN=71, TP=6
- **UNSW-NB15 Model**: TN=0, FP=10, FN=1, TP=426
- **CTU-13 Model**: TN=142, FP=52, FN=370, TP=1,791
- **SUM OF INDEPENDENT DATASET MODELS**:
  $$\text{TN} = \mathbf{588}, \quad \text{FP} = \mathbf{262}, \quad \text{FN} = \mathbf{442}, \quad \text{TP} = \mathbf{2,223}$$
  - $\text{Attack Precision} = \mathbf{0.8946}, \text{Attack Recall} = \mathbf{0.8341}, \text{Attack F1} = \mathbf{0.8633}, \text{FPR} = \mathbf{30.82\%}$
- **POOLED MASTER MODEL**:
  - $\text{TN}=799, \text{FP}=51, \text{FN}=635, \text{TP}=2,030$
  - $\text{Attack F1} = \mathbf{0.8555}, \text{Prec} = \mathbf{0.9755}, \text{Rec} = \mathbf{0.7617}, \text{FPR} = \mathbf{6.00\%}$

---

## 3. Summary Conclusion

Both reporting methods are valid representations of different operational scenarios:
1. **Dataset-Summed Evaluation** measures domain-specialized classifiers deployed in their respective network environments.
2. **Pooled Model Evaluation** measures a single cross-domain classifier exposed to heterogeneous traffic distributions.

In all subsequent three-model comparisons, both metrics will be reported clearly so no ambiguity exists.
