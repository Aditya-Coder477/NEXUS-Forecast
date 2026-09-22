# NEXUS-Forecast Data Governance & Management Guide

This document establishes the official data management policy, inventory records, cleanup decisions, storage accounting, and reproducibility guidelines for the **NEXUS-Forecast** project.

---

## 1. Datasets Overview

| Dataset / Knowledge Base | Type | Files | Original Footprint | Primary Role in NEXUS-Forecast | Status |
|---|---|---|---|---|---|
| **CIC-IDS2017** | Empirical Traffic | 28 | 50.78 GB | Primary multi-attack flow sequences & ground-truth validation | **PROTECTED / UNTOUCHED** |
| **UNSW-NB15** | Empirical Traffic | 4 | 1.97 GB | Supplementary flow dataset for cross-dataset generalization | **PROTECTED / UNTOUCHED** |
| **CTU-13** | Empirical Traffic | 52 | 74.27 GB | Botnet C2 behavioral analysis & flow forecasting | **FLOW KEPT; PCAP CANDIDATE** |
| **MITRE ATT&CK** | Knowledge Base | 7 | 51.34 MB (raw) | Primary adversary tactics/techniques & stage explainability | **ACQUIRED (v19.2)** |
| **CAPEC** | Knowledge Base | 8 | ~10 MB | Attack mechanism abstractions & CWE enrichment | **INTEGRATED (v3.9)** |
| **NVD / CVE** | Vulnerability DB | 0 | 0 MB | Not applicable for flow-level temporal modeling | **EXCLUDED BY DESIGN** |

---

## 2. Dataset Specific Profiles

### A. CIC-IDS2017 (50.78 GB)
- **Directory**: `data/CIC-IDS2017/`
- **Contents**:
  - `PCAP/`: 5 raw PCAP captures representing Friday, Monday, Thursday, Tuesday, and Wednesday working hours (total: 51.98 GB) with MD5 checksums.
  - `CSV/`: Flow feature sets generated via CICFlowMeter (`GeneratedLabelledFlows/` and `MachineLearningCSV/`, 16 CSVs total: 2.54 GB) with MD5 checksums.
- **Role**: Serves as the primary training and benchmark ground truth for temporal world-model training across modern enterprise attacks (DoS, DDoS, PortScan, Brute Force, Web Attacks, Botnet, Infiltration).
- **Governance Policy**: **STRICTLY PROTECTED**. No files modified, deleted, or relocated.

### B. UNSW-NB15 (1.97 GB)
- **Directory**: `data/UNSW-NB15/`
- **Contents**:
  - `CICFlowMeter_out.csv` (1.78 GB)
  - `Data.csv` (187.16 MB)
  - `Label.csv` (874.84 KB)
  - `Readme.txt` (111 bytes)
- **Role**: Realistic background traffic and structured attack behaviors for testing temporal sequence transferability.
- **Governance Policy**: **STRICTLY PROTECTED**. No files modified, deleted, or relocated.

### C. CTU-13 Dataset (74.27 GB)
- **Directory**: `data/CTU-13-Dataset/` (13 Scenarios)
- **Role**: Botnet C2 traffic analysis, periodic beaconing detection, and independent temporal validation across 7 distinct malware strains (Neris, Rbot, Virut, Donbot, Sogou, Qvod, NSIS.ay).
- **Cleanup Evaluation & Decisions**:
  - **Raw PCAP (13 files, 71.72 GB)**: Marked as `DELETE` candidates. Specifically, Scenario 10 alone consumed 70.68 GB. Each PCAP has a verified corresponding `.binetflow` file.
  - **Binetflow Files (13 files, 2.54 GB)**: Marked as `KEEP`. These Argus-generated bidirectional NetFlow records contain full flow metadata (`StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label`) and are 100% sufficient for flow-level temporal modeling.
  - **Malware Binaries (13 `.exe` files, 8.71 MB)**: Marked as `REVIEW_REQUIRED`. Preserved intact to prevent accidental loss of sandbox reference artifacts.
  - **Scenario Documentation (13 README files)**: Marked as `KEEP`.
- **Reproducibility Note & Known Limitation**:
  - *Limitation*: Deleting the raw PCAP files removes the ability to perform future packet-payload inspection or regenerate alternate flow features from scratch.
  - *Mitigation*: The retained `.binetflow` representation is the canonical CTU-13 artifact used in academic benchmarks and contains complete ground-truth labels for temporal forecasting.

### D. MITRE ATT&CK Knowledge Layer (Enterprise v19.2)
- **Directory**: `data/knowledge/mitre_attack/`
- **Source**: Official Enterprise ATT&CK STIX 2.1 Release (`2026-08-05`).
- **Raw Storage**: `data/knowledge/mitre_attack/raw/enterprise-attack-19.2.json` (SHA-256: `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`).
- **Processed Files**:
  - `tactics.json` (15 tactics)
  - `techniques.json` (222 parent techniques)
  - `subtechniques.json` (475 sub-techniques)
  - `relationships.json` (21,262 STIX relationship edges)
  - `nexus_forecast_attack_knowledge.json` (210 curated network-relevant techniques)
  - `attack_stage_mapping.json` (210 application-level stage mappings: 191 `HIGH` confidence, 19 `REVIEW_REQUIRED` multi-tactic entries).

### E. CAPEC Knowledge Layer (v3.9)
- **Directory**: `data/knowledge/capec/`
- **Source**: MITRE CAPEC v3.9 (`2023-01-24`).
- **Raw Storage**: `data/knowledge/capec/raw/capec_latest.xml` (SHA-256: `02302bb6beff769d4d54da138ffbc0db8182747ff22ff2e4dd092d6e38466bb2`) plus view archives `333.csv.zip`, `658.csv.zip`, `659.csv.zip`.
- **Processed Storage**: `data/knowledge/capec/processed/capec_normalized.json` (615 normalized attack patterns, 272 official ATT&CK links).
- **Metadata**: `data/knowledge/capec/metadata.json`.

### F. NVD / CVE Exclusion Policy
- NVD/CVE is **excluded by design**. Host-level CVE vulnerabilities are not observable in encrypted or statistical NetFlow streams without host agents or deep payload inspection. NEXUS-Forecast focuses on behavioral temporal progression rather than vulnerability enumeration.

---

## 3. Storage Analysis & Space Recovery

| Component | Before Cleanup | Proposed Retained | Proposed Deletions | Space Recovered |
|---|---|---|---|---|
| **CIC-IDS2017** | 50.78 GB | 50.78 GB | 0 bytes | 0 GB |
| **UNSW-NB15** | 1.97 GB | 1.97 GB | 0 bytes | 0 GB |
| **CTU-13 Dataset** | 74.27 GB | 2.55 GB | 71.72 GB | **71.72 GB** |
| **MITRE ATT&CK** | 0 GB | 0.06 GB | 0 bytes | (Acquired) |
| **CAPEC** | 0.01 GB | 0.01 GB | 0 bytes | 0 GB |
| **Total Project** | **127.02 GB** | **55.37 GB** | **71.72 GB** | **~71.72 GB (56.5% reduction)** |

---

## 4. CTU-13 Cleanup Execution Procedure

1. **Verify Plan**:
   Inspect `data/ctu13_deletion_plan.csv`.
2. **Execute Dry-Run** (Default):
   ```bash
   python src/data_management/cleanup_ctu13.py --dry-run
   ```
   Inspect `data/ctu13_cleanup_log.json` to confirm simulated targets.
3. **Execute Real Cleanup** (Explicit):
   ```bash
   python src/data_management/cleanup_ctu13.py --execute
   ```
4. **Regenerate Inventory**:
   ```bash
   python src/data_management/generate_inventory.py --prefix data_inventory_after_cleanup
   ```
