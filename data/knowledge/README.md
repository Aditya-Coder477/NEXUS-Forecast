# NEXUS-Forecast Knowledge Layer Documentation

This directory contains the semantic cybersecurity knowledge architecture for **NEXUS-Forecast**.

---

## 1. Architectural Role in NEXUS-Forecast

The core engine of NEXUS-Forecast is a temporal world model that forecasts multi-step network attack progressions from observed NetFlow/Binetflow telemetry.

```
Network Traffic
      ↓
Network Evidence / Features (Duration, Protocol, Packet/Byte Rates, State Transitions)
      ↓
NEXUS-Forecast World Model (Temporal State & Sequence Forecasting)
      ↓
Forecasted Attack Stage (BENIGN, RECONNAISSANCE, INITIAL_ACCESS, ..., EXFILTRATION)
      ↓
MITRE ATT&CK Technique (Adversary Tactic & Technique Context)
      ↓
CAPEC Attack Pattern (Detailed Attack Mechanism & Weakness Enrichment)
```

### Key Principles:
- **Knowledge, Not Training Data**: Neither MITRE ATT&CK nor CAPEC is used as the primary machine learning training data. The forecasting model is trained on empirical network flow sequences (CIC-IDS2017, UNSW-NB15, CTU-13).
- **Post-Inference Semantic Enrichment**: ATT&CK and CAPEC serve as the operational interpretation, stage explanation, and explainability layers for security operations center (SOC) analysts.
- **Strict Non-Fabrication**: Mappings between ATT&CK and CAPEC are exclusively derived from official MITRE taxonomy publications without speculative or synthesized links.

---

## 2. MITRE ATT&CK Integration

### Rationale:
MITRE ATT&CK (Enterprise) provides a standardized, industry-wide taxonomy of real-world adversary behaviors across the entire intrusion lifecycle. It allows NEXUS-Forecast to translate abstract temporal state transitions into actionable adversary tactics and techniques.

### Source & Acquisition Metadata:
- **Domain**: Enterprise ATT&CK
- **Release Version**: `v19.2`
- **Official Source**: [mitre-attack/attack-stix-data Releases](https://github.com/mitre-attack/attack-stix-data/releases/tag/v19.2)
- **Source URL**: `https://github.com/mitre-attack/attack-stix-data/releases/download/v19.2/enterprise-attack.json`
- **Release Date**: `2026-08-05T22:58:54Z`
- **Acquisition Date**: `2026-09-21`
- **File Size**: `53,835,637 bytes (51.34 MB)`
- **SHA-256 Checksum**: `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`

### Raw vs. Processed Representation:
- **Raw**: Stored immutably at `data/knowledge/mitre_attack/raw/enterprise-attack-19.2.json` (26,086 STIX objects).
- **Processed**:
  - `tactics.json`: 15 Enterprise tactics (TA0043, TA0001, etc.).
  - `techniques.json`: 222 parent techniques.
  - `subtechniques.json`: 475 sub-techniques with parent relationships.
  - `relationships.json`: 21,262 STIX relationship edges (`subtechnique-of`, `uses`, `mitigates`).
  - `nexus_forecast_attack_knowledge.json`: 210 curated network-relevant techniques.
  - `attack_stage_mapping.json`: 210 application-level stage mappings.

### NEXUS-Forecast Relevance Filtering:
Out of 697 total techniques and sub-techniques, 210 are curated for network attack forecasting based on:
1. Explicit prioritization of network attack families (Reconnaissance scanning, public-facing exploitation, credential brute force, remote services, C2 protocols, data exfiltration).
2. STIX objects explicitly tagged with `x_mitre_network_requirements: true`.
3. Network-observable behavioral keywords (scanning, traffic, protocol, port, SMB, RDP, SSH, proxy, beaconing).

### Application-Level Stage Mapping:
NEXUS-Forecast maps curated techniques into 9 conceptual stages:
`BENIGN`, `RECONNAISSANCE`, `INITIAL_ACCESS`, `EXECUTION`, `DISCOVERY`, `CREDENTIAL_ACCESS`, `LATERAL_MOVEMENT`, `COMMAND_AND_CONTROL`, `EXFILTRATION`.
- **Transparency Guarantee**: ATT&CK defines official tactics; the NEXUS stages are an application-level grouping. Every mapping records `mapping_confidence` (`HIGH` for 191 single-tactic techniques, `REVIEW_REQUIRED` for 19 multi-tactic techniques) and `mapping_reason`.

---

## 3. CAPEC Integration

### Rationale:
CAPEC (Common Attack Pattern Enumeration and Classification) provides deep architectural context on attack mechanisms, prerequisites, and affected software weaknesses (CWE). While ATT&CK describes *what* adversaries do, CAPEC describes *how* specific exploit mechanisms unfold.

### Source & Acquisition Metadata:
- **Catalog**: MITRE CAPEC Version 3.9
- **Release Date**: `2023-01-24`
- **Source URL**: `https://capec.mitre.org/data/xml/views/3000.xml`
- **Acquisition Date**: `2026-09-21`
- **Source Files**: `data/knowledge/capec/raw/capec_latest.xml` (3,849,998 bytes), accompanied by view archives `333.csv.zip`, `658.csv.zip`, `659.csv.zip`.
- **SHA-256 Checksum (capec_latest.xml)**: `02302bb6beff769d4d54da138ffbc0db8182747ff22ff2e4dd092d6e38466bb2`

### Processed Artifacts:
- `data/knowledge/capec/processed/capec_normalized.json`: 615 normalized attack pattern definitions containing:
  - CAPEC ID, Name, Abstraction Level, Description
  - Typical Severity, Likelihood of Attack
  - Prerequisites and Consequences (scopes and impacts)
  - Related Attack Patterns and Related Weaknesses (CWE IDs)
  - Documented Taxonomy Mappings (272 official ATT&CK links)
- `data/knowledge/capec/metadata.json`: Complete audit manifest of raw files, checksums, and counts.

---

## 4. Exclusion of NVD/CVE

NVD (National Vulnerability Database) and CVE data are **intentionally excluded** from this phase of NEXUS-Forecast by design:
1. **Network Flow Granularity**: Temporal network state forecasting operates at the flow level (IP, port, protocol, packet timing, byte distributions), where specific host-level CVE identifiers cannot be reliably observed without full payload decapsulation and endpoint vulnerability telemetry.
2. **Computational Footprint**: Retaining full NVD feeds introduces massive JSON payloads without adding predictive value to the macro-level attack stage forecasting model.
3. **Focus on Behavioral Patterns**: MITRE ATT&CK and CAPEC represent adversary behaviors and mechanisms, which generalize across vulnerabilities and novel zero-day exploits much better than static CVE vulnerability lists.

---

## 5. Offline-First Requirement & Air-Gapped Operation

NEXUS-Forecast is designed to operate completely offline during evaluation (e.g., Smart India Hackathon demonstrations):
- **Zero Runtime Network Calls**: Inference and dashboard rendering never query the MITRE website, CAPEC portal, or external web APIs.
- **In-Memory Loading**: The Python interface (`src/data_management/knowledge_loader.py`) loads all knowledge assets locally into optimized memory structures in **< 60 ms**.
- **Deterministic**: Knowledge lookups are hash-indexed and deterministic across restarts.

---

## 6. Update Procedure

When a new version of Enterprise ATT&CK or CAPEC is released:
1. Download the new STIX JSON release asset from the official repository into `data/knowledge/mitre_attack/raw/enterprise-attack-<NEW_VERSION>.json`.
2. Execute the extraction pipeline:
   ```bash
   python src/data_management/extract_mitre.py
   python src/data_management/generate_knowledge_schema.py
   ```
3. Run the validation suite:
   ```bash
   python src/data_management/validate_knowledge.py
   ```
4. Verify checksums and ensure no existing datasets (`CIC-IDS2017`, `UNSW-NB15`, `CAPEC raw`) were modified.
