# MITRE ATT&CK v19.2 Stage Mapping & Tactic Validation Report

**Date**: 2026-09-21  
**Target Knowledge Layer**: `data/knowledge/mitre_attack/processed/attack_stage_mapping.json`  
**Reference Source**: MITRE Enterprise ATT&CK v19.2 STIX Release (`enterprise-attack-19.2.json`, SHA-256: `dc1639caa5501d72...`)

---

## 1. Summary of Stage Mappings

- **Total Curated Mappings**: 210
- **HIGH Confidence Mappings**: 191 (Unambiguous, single-tactic network techniques)
- **REVIEW_REQUIRED Mappings**: 19 (Multi-tactic techniques requiring temporal session context)
- **Multi-Tactic Techniques**: 19 (Exactly matches `REVIEW_REQUIRED` set)
- **Invalid / Fabricated Tactic Names**: **0**

---

## 2. Investigation of `"stealth"` Tactic

### User Inquiry:
Inspect whether `"stealth"` in `all_mitre_tactics` (e.g. in `T1078 Valid Accounts` and `T1205 Traffic Signaling`) is a valid ATT&CK tactic in the source STIX data or an extraction/mapping artifact.

### Empirical STIX v19.2 Verification:
Direct inspection of the official MITRE Enterprise ATT&CK v19.2 STIX bundle (`enterprise-attack-19.2.json`) confirms that **`"stealth"` is an official, valid ATT&CK tactic in v19.2**, and is **NOT an extraction artifact**.

Specifically:
1. **STIX `x-mitre-tactic` Object**:
   - **ID**: `x-mitre-tactic--d108dae8-971c-4b53-9f4c-1d378ee094a9`
   - **External ID**: `TA0005`
   - **Name**: `"Stealth"`
   - **Shortname / Phase Name**: `"stealth"`
   *(Note: In earlier ATT&CK revisions prior to v19, TA0005 was historically named "Defense Evasion". In ATT&CK v19.2, MITRE structured TA0005 as "Stealth" while introducing TA0112 as "Defense Impairment" with shortname `defense-impairment`)*.

2. **Raw STIX Kill Chain Phases for T1078**:
   ```json
   {
     "type": "attack-pattern",
     "name": "Valid Accounts",
     "external_id": "T1078",
     "kill_chain_phases": [
       {"kill_chain_name": "mitre-attack", "phase_name": "stealth"},
       {"kill_chain_name": "mitre-attack", "phase_name": "persistence"},
       {"kill_chain_name": "mitre-attack", "phase_name": "privilege-escalation"},
       {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
     ]
   }
   ```
3. **Conclusion**:
   The value `"stealth"` is genuine, verbatim MITRE ATT&CK v19.2 taxonomy terminology. No extraction or mapping artifacts occurred.

---

## 3. Detailed Audit of all 19 `REVIEW_REQUIRED` Entries

All 19 entries were verified against their raw STIX objects. In accordance with project instructions, **none of these entries are forced into a single definitive stage**. They remain designated as `REVIEW_REQUIRED` priors for temporal world-model contextual disambiguation:

| ATT&CK ID | Technique Name | Official STIX v19.2 Tactics | Mapping Confidence | Architectural Rationale for Temporal Disambiguation |
|---|---|---|---|---|
| **T1040** | Network Sniffing | `credential-access`, `discovery` | `REVIEW_REQUIRED` | May serve as passive credential harvesting or subnet reconnaissance depending on packet capture duration and target hosts. |
| **T1053** | Scheduled Task/Job | `execution`, `persistence`, `privilege-escalation` | `REVIEW_REQUIRED` | Initial creation is Execution; scheduled recurrence represents Persistence; elevated token context indicates Privilege Escalation. |
| **T1053.002** | At | `execution`, `persistence`, `privilege-escalation` | `REVIEW_REQUIRED` | Sub-technique of T1053. |
| **T1053.003** | Cron | `execution`, `persistence`, `privilege-escalation` | `REVIEW_REQUIRED` | Sub-technique of T1053. |
| **T1053.005** | Scheduled Task | `execution`, `persistence`, `privilege-escalation` | `REVIEW_REQUIRED` | Sub-technique of T1053. |
| **T1053.006** | Systemd Timers | `execution`, `persistence`, `privilege-escalation` | `REVIEW_REQUIRED` | Sub-technique of T1053. |
| **T1053.007** | Container Orchestration Job | `execution`, `persistence`, `privilege-escalation` | `REVIEW_REQUIRED` | Sub-technique of T1053. |
| **T1072** | Software Deployment Tools | `execution`, `lateral-movement` | `REVIEW_REQUIRED` | Tool execution on local manager vs push deployment across internal subnets represents Lateral Movement. |
| **T1078** | Valid Accounts | `stealth`, `persistence`, `privilege-escalation`, `initial-access` | `REVIEW_REQUIRED` | External ingress logon = Initial Access; dormant domain account = Persistence; elevated role = Privilege Escalation; blending with baseline = Stealth. |
| **T1078.001** | Default Accounts | `stealth`, `persistence`, `privilege-escalation`, `initial-access` | `REVIEW_REQUIRED` | Sub-technique of T1078. |
| **T1078.002** | Domain Accounts | `stealth`, `persistence`, `privilege-escalation`, `initial-access` | `REVIEW_REQUIRED` | Sub-technique of T1078. |
| **T1078.003** | Local Accounts | `stealth`, `persistence`, `privilege-escalation`, `initial-access` | `REVIEW_REQUIRED` | Sub-technique of T1078. |
| **T1078.004** | Cloud Accounts | `stealth`, `persistence`, `privilege-escalation`, `initial-access` | `REVIEW_REQUIRED` | Sub-technique of T1078. |
| **T1091** | Replication Through Removable Media | `lateral-movement`, `initial-access` | `REVIEW_REQUIRED` | Initial physical insertion vs internal propagation across disconnected segments. |
| **T1133** | External Remote Services | `persistence`, `initial-access` | `REVIEW_REQUIRED` | VPN/RDP gateway ingress: Initial entrypoint vs maintaining redundant persistent access. |
| **T1205** | Traffic Signaling | `stealth`, `persistence`, `command-and-control` | `REVIEW_REQUIRED` | Knock sequence = C2 handshake / stealth evasion; listener persistence on host. |
| **T1205.001** | Port Knocking | `stealth`, `persistence`, `command-and-control` | `REVIEW_REQUIRED` | Sub-technique of T1205. |
| **T1205.002** | Socket Filters | `stealth`, `persistence`, `command-and-control` | `REVIEW_REQUIRED` | Sub-technique of T1205. |
| **T1659** | Content Injection | `initial-access`, `command-and-control` | `REVIEW_REQUIRED` | Upstream in-transit payload modification (Initial Access) vs C2 channel manipulation. |

---

## 4. Complete List of 15 Valid STIX Enterprise v19.2 Tactics

1. `TA0043` - **Reconnaissance** (`shortname: reconnaissance`)
2. `TA0042` - **Resource Development** (`shortname: resource-development`)
3. `TA0001` - **Initial Access** (`shortname: initial-access`)
4. `TA0002` - **Execution** (`shortname: execution`)
5. `TA0003` - **Persistence** (`shortname: persistence`)
6. `TA0004` - **Privilege Escalation** (`shortname: privilege-escalation`)
7. `TA0005` - **Stealth** (`shortname: stealth`)
8. `TA0112` - **Defense Impairment** (`shortname: defense-impairment`)
9. `TA0006` - **Credential Access** (`shortname: credential-access`)
10. `TA0007` - **Discovery** (`shortname: discovery`)
11. `TA0008` - **Lateral Movement** (`shortname: lateral-movement`)
12. `TA0009` - **Collection** (`shortname: collection`)
13. `TA0011` - **Command and Control** (`shortname: command-and-control`)
14. `TA0010` - **Exfiltration** (`shortname: exfiltration`)
15. `TA0040` - **Impact** (`shortname: impact`)
