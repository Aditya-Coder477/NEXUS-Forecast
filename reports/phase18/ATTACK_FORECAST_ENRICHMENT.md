# NEXUS-Forecast SOC Intelligence Report: SCENARIO-PORT-SCAN
**Timestamp**: `2026-09-21T19:57:11.166530+00:00` | **Origin Window Index**: `0`
**Overall Threat Status**: `ATTACK FORECASTED`
**Forecast Trajectory**: `RECONNAISSANCE -> DISCOVERY -> INITIAL_ACCESS`
**Active Evidence Categories**: `CONNECTION_BEHAVIOR, HOST_DIVERSITY, PORT_DIVERSITY, TRAFFIC_VOLUME`

---
## Horizon Breakdown & MITRE ATT&CK / CAPEC Mapping

### Horizon H1 (Step +1 / +30s)
- **Prediction**: **ATTACK** (Calibrated Probability: **89.20%**)
- **Predicted Stage**: `RECONNAISSANCE` (Stage Confidence: **94.00%**)

#### Contextually Relevant & Evidence-Supported ATT&CK Techniques:
| ATT&CK ID | Technique Name | Relevance Tier | Confidence | Evidence Notes |
| :--- | :--- | :--- | :--- | :--- |
| `T1595.001` | Scanning IP Blocks | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: PORT_DIVERSITY. |
| `T1595.002` | Vulnerability Scanning | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: PORT_DIVERSITY. |
| `T1589` | Gather Victim Identity Information | CONTEXTUALLY_RELEVANT | `HIGH` | Contextually aligned with predicted attack stage, but no direct matching category anomaly. |
| `T1589.001` | Credentials | CONTEXTUALLY_RELEVANT | `HIGH` | Contextually aligned with predicted attack stage, but no direct matching category anomaly. |
| `T1589.002` | Email Addresses | CONTEXTUALLY_RELEVANT | `HIGH` | Contextually aligned with predicted attack stage, but no direct matching category anomaly. |
| `T1589.003` | Employee Names | CONTEXTUALLY_RELEVANT | `HIGH` | Contextually aligned with predicted attack stage, but no direct matching category anomaly. |
| `T1590` | Gather Victim Network Information | CONTEXTUALLY_RELEVANT | `HIGH` | Contextually aligned with predicted attack stage, but no direct matching category anomaly. |
| `T1590.001` | Domain Properties | CONTEXTUALLY_RELEVANT | `HIGH` | Contextually aligned with predicted attack stage, but no direct matching category anomaly. |

#### Associated CAPEC Attack Patterns:
| CAPEC ID | Pattern Name | Severity | Relevance | Likelihood |
| :--- | :--- | :--- | :--- | :--- |
| `CAPEC-309` | Network Topology Mapping | `Low` | **EVIDENCE_SUPPORTED** | `Medium` |
| `CAPEC-169` | Footprinting | `Very Low` | CONTEXTUALLY_RELEVANT | `High` |
| `CAPEC-407` | Pretexting | `Low` | CONTEXTUALLY_RELEVANT | `Medium` |


### Horizon H3 (Step +3 / +90s)
- **Prediction**: **ATTACK** (Calibrated Probability: **94.10%**)
- **Predicted Stage**: `DISCOVERY` (Stage Confidence: **88.00%**)

#### Contextually Relevant & Evidence-Supported ATT&CK Techniques:
| ATT&CK ID | Technique Name | Relevance Tier | Confidence | Evidence Notes |
| :--- | :--- | :--- | :--- | :--- |
| `T1018` | Remote System Discovery | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: HOST_DIVERSITY. |
| `T1046` | Network Service Discovery | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: CONNECTION_BEHAVIOR, HOST_DIVERSITY, PORT_DIVERSITY. |
| `T1016` | System Network Configuration Discovery | CONTEXTUALLY_RELEVANT | `HIGH` | Contextually aligned with predicted attack stage, but no direct matching category anomaly. |
| `T1016.001` | Internet Connection Discovery | CONTEXTUALLY_RELEVANT | `HIGH` | Contextually aligned with predicted attack stage, but no direct matching category anomaly. |
| `T1016.002` | Wi-Fi Discovery | CONTEXTUALLY_RELEVANT | `HIGH` | Contextually aligned with predicted attack stage, but no direct matching category anomaly. |
| `T1069` | Permission Groups Discovery | CONTEXTUALLY_RELEVANT | `HIGH` | Contextually aligned with predicted attack stage, but no direct matching category anomaly. |
| `T1069.001` | Local Groups | CONTEXTUALLY_RELEVANT | `HIGH` | Contextually aligned with predicted attack stage, but no direct matching category anomaly. |
| `T1069.002` | Domain Groups | CONTEXTUALLY_RELEVANT | `HIGH` | Contextually aligned with predicted attack stage, but no direct matching category anomaly. |

#### Associated CAPEC Attack Patterns:
| CAPEC ID | Pattern Name | Severity | Relevance | Likelihood |
| :--- | :--- | :--- | :--- | :--- |
| `CAPEC-292` | Host Discovery | `Low` | **EVIDENCE_SUPPORTED** | `Medium` |
| `CAPEC-300` | Port Scanning | `Low` | **EVIDENCE_SUPPORTED** | `Medium` |
| `CAPEC-309` | Network Topology Mapping | `Low` | **EVIDENCE_SUPPORTED** | `Medium` |
| `CAPEC-576` | Group Permission Footprinting | `Low` | CONTEXTUALLY_RELEVANT | `Low` |


### Horizon H6 (Step +6 / +180s)
- **Prediction**: **ATTACK** (Calibrated Probability: **96.50%**)
- **Predicted Stage**: `INITIAL_ACCESS` (Stage Confidence: **82.00%**)

#### Contextually Relevant & Evidence-Supported ATT&CK Techniques:
| ATT&CK ID | Technique Name | Relevance Tier | Confidence | Evidence Notes |
| :--- | :--- | :--- | :--- | :--- |
| `T1190` | Exploit Public-Facing Application | CONTEXTUALLY_RELEVANT | `HIGH` | Contextually aligned with predicted attack stage, but no direct matching category anomaly. |
| `T1200` | Hardware Additions | CONTEXTUALLY_RELEVANT | `HIGH` | Contextually aligned with predicted attack stage, but no direct matching category anomaly. |
| `T1078` | Valid Accounts | REVIEW_REQUIRED | `REVIEW_REQUIRED` | Manual SOC analyst review required due to ambiguous or multi-tactic classification. |
| `T1078.001` | Default Accounts | REVIEW_REQUIRED | `REVIEW_REQUIRED` | Manual SOC analyst review required due to ambiguous or multi-tactic classification. |
| `T1078.002` | Domain Accounts | REVIEW_REQUIRED | `REVIEW_REQUIRED` | Manual SOC analyst review required due to ambiguous or multi-tactic classification. |
| `T1078.003` | Local Accounts | REVIEW_REQUIRED | `REVIEW_REQUIRED` | Manual SOC analyst review required due to ambiguous or multi-tactic classification. |
| `T1078.004` | Cloud Accounts | REVIEW_REQUIRED | `REVIEW_REQUIRED` | Manual SOC analyst review required due to ambiguous or multi-tactic classification. |
| `T1133` | External Remote Services | REVIEW_REQUIRED | `REVIEW_REQUIRED` | Manual SOC analyst review required due to ambiguous or multi-tactic classification. |

#### Associated CAPEC Attack Patterns:
| CAPEC ID | Pattern Name | Severity | Relevance | Likelihood |
| :--- | :--- | :--- | :--- | :--- |
| `CAPEC-440` | Hardware Integrity Attack | `High` | CONTEXTUALLY_RELEVANT | `Low` |
| `CAPEC-70` | Try Common or Default Usernames and Passwords | `High` | REVIEW_REQUIRED | `Medium` |
| `CAPEC-555` | Remote Services with Stolen Credentials | `Very High` | REVIEW_REQUIRED | `Medium` |
| `CAPEC-560` | Use of Known Domain Credentials | `High` | REVIEW_REQUIRED | `High` |

> [!WARNING]
> **Techniques Requiring SOC Analyst Review (6)**:
> - `T1078 (Valid Accounts)`
> - `T1078.001 (Default Accounts)`
> - `T1078.002 (Domain Accounts)`
> - `T1078.003 (Local Accounts)`
> - `T1078.004 (Cloud Accounts)`
> - `T1133 (External Remote Services)`


---
### Epistemic Boundary Notice
> [!NOTE]
> All MITRE ATT&CK techniques and CAPEC patterns surfaced above represent structured contextual knowledge associations derived from macroscopic network telemetry and sequence modeling. They do **not** constitute definitive forensic proof of malicious execution or endpoint compromise.

# NEXUS-Forecast SOC Intelligence Report: SCENARIO-C2-EXFIL
**Timestamp**: `2026-09-21T19:57:11.170942+00:00` | **Origin Window Index**: `0`
**Overall Threat Status**: `ATTACK FORECASTED`
**Forecast Trajectory**: `COMMAND_AND_CONTROL -> COMMAND_AND_CONTROL -> EXFILTRATION`
**Active Evidence Categories**: `DIRECTIONALITY, PROTOCOL_BEHAVIOR, TRAFFIC_VOLUME`

---
## Horizon Breakdown & MITRE ATT&CK / CAPEC Mapping

### Horizon H1 (Step +1 / +30s)
- **Prediction**: **ATTACK** (Calibrated Probability: **91.50%**)
- **Predicted Stage**: `COMMAND_AND_CONTROL` (Stage Confidence: **92.00%**)

#### Contextually Relevant & Evidence-Supported ATT&CK Techniques:
| ATT&CK ID | Technique Name | Relevance Tier | Confidence | Evidence Notes |
| :--- | :--- | :--- | :--- | :--- |
| `T1001` | Data Obfuscation | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: PROTOCOL_BEHAVIOR. |
| `T1001.001` | Junk Data | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: PROTOCOL_BEHAVIOR, TRAFFIC_VOLUME. |
| `T1001.002` | Steganography | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: PROTOCOL_BEHAVIOR. |
| `T1001.003` | Protocol or Service Impersonation | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: PROTOCOL_BEHAVIOR. |
| `T1071` | Application Layer Protocol | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: DIRECTIONALITY, PROTOCOL_BEHAVIOR. |
| `T1071.001` | Web Protocols | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: DIRECTIONALITY, PROTOCOL_BEHAVIOR. |
| `T1071.002` | File Transfer Protocols | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: DIRECTIONALITY, PROTOCOL_BEHAVIOR. |
| `T1071.003` | Mail Protocols | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: DIRECTIONALITY, PROTOCOL_BEHAVIOR. |

#### Associated CAPEC Attack Patterns:
| CAPEC ID | Pattern Name | Severity | Relevance | Likelihood |
| :--- | :--- | :--- | :--- | :--- |
| `CAPEC-636` | Hiding Malicious Data or Code within Files | `High` | **EVIDENCE_SUPPORTED** | `Medium` |


### Horizon H3 (Step +3 / +90s)
- **Prediction**: **ATTACK** (Calibrated Probability: **95.20%**)
- **Predicted Stage**: `COMMAND_AND_CONTROL` (Stage Confidence: **95.00%**)

#### Contextually Relevant & Evidence-Supported ATT&CK Techniques:
| ATT&CK ID | Technique Name | Relevance Tier | Confidence | Evidence Notes |
| :--- | :--- | :--- | :--- | :--- |
| `T1001` | Data Obfuscation | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: PROTOCOL_BEHAVIOR. |
| `T1001.001` | Junk Data | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: PROTOCOL_BEHAVIOR, TRAFFIC_VOLUME. |
| `T1001.002` | Steganography | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: PROTOCOL_BEHAVIOR. |
| `T1001.003` | Protocol or Service Impersonation | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: PROTOCOL_BEHAVIOR. |
| `T1071` | Application Layer Protocol | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: DIRECTIONALITY, PROTOCOL_BEHAVIOR. |
| `T1071.001` | Web Protocols | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: DIRECTIONALITY, PROTOCOL_BEHAVIOR. |
| `T1071.002` | File Transfer Protocols | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: DIRECTIONALITY, PROTOCOL_BEHAVIOR. |
| `T1071.003` | Mail Protocols | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: DIRECTIONALITY, PROTOCOL_BEHAVIOR. |

#### Associated CAPEC Attack Patterns:
| CAPEC ID | Pattern Name | Severity | Relevance | Likelihood |
| :--- | :--- | :--- | :--- | :--- |
| `CAPEC-636` | Hiding Malicious Data or Code within Files | `High` | **EVIDENCE_SUPPORTED** | `Medium` |


### Horizon H6 (Step +6 / +180s)
- **Prediction**: **ATTACK** (Calibrated Probability: **98.10%**)
- **Predicted Stage**: `EXFILTRATION` (Stage Confidence: **89.00%**)

#### Contextually Relevant & Evidence-Supported ATT&CK Techniques:
| ATT&CK ID | Technique Name | Relevance Tier | Confidence | Evidence Notes |
| :--- | :--- | :--- | :--- | :--- |
| `T1020` | Automated Exfiltration | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: DIRECTIONALITY, TRAFFIC_VOLUME. |
| `T1020.001` | Traffic Duplication | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: DIRECTIONALITY, TRAFFIC_VOLUME. |
| `T1041` | Exfiltration Over C2 Channel | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: DIRECTIONALITY. |
| `T1048` | Exfiltration Over Alternative Protocol | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: DIRECTIONALITY, TRAFFIC_VOLUME. |
| `T1048.001` | Exfiltration Over Symmetric Encrypted Non-C2 Protocol | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: DIRECTIONALITY, TRAFFIC_VOLUME. |
| `T1048.002` | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: DIRECTIONALITY, TRAFFIC_VOLUME. |
| `T1048.003` | Exfiltration Over Unencrypted Non-C2 Protocol | **EVIDENCE_SUPPORTED** | `HIGH` | Supported by observed network evidence in: DIRECTIONALITY, TRAFFIC_VOLUME. |
| `T1011` | Exfiltration Over Other Network Medium | CONTEXTUALLY_RELEVANT | `HIGH` | Contextually aligned with predicted attack stage, but no direct matching category anomaly. |

#### Associated CAPEC Attack Patterns:
*(No associated CAPEC patterns identified)*


---
### Epistemic Boundary Notice
> [!NOTE]
> All MITRE ATT&CK techniques and CAPEC patterns surfaced above represent structured contextual knowledge associations derived from macroscopic network telemetry and sequence modeling. They do **not** constitute definitive forensic proof of malicious execution or endpoint compromise.