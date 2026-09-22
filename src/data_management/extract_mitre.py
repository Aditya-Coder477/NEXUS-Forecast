"""
Parser and extractor for MITRE ATT&CK STIX bundle.
Extracts tactics, techniques, subtechniques, relationships,
generates curated NEXUS-Forecast relevant knowledge, and builds
transparent application-level stage mappings.
"""

import os
import json
from datetime import datetime, timezone

def extract_mitre_data(raw_file="data/knowledge/mitre_attack/raw/enterprise-attack-19.2.json",
                       output_dir="data/knowledge/mitre_attack/processed"):
    os.makedirs(output_dir, exist_ok=True)
    print(f"Loading raw STIX bundle: {raw_file}...")

    with open(raw_file, "r", encoding="utf-8") as f:
        stix_bundle = json.load(f)

    objects = stix_bundle.get("objects", [])
    print(f"Total STIX objects loaded: {len(objects)}")

    # Containers
    tactics = []
    techniques = []
    subtechniques = []
    relationships = []

    # Lookup tables
    tactic_shortname_to_id = {}
    obj_id_to_external_id = {}
    obj_id_to_name = {}

    # Pass 1: Extract tactics and index object IDs
    for obj in objects:
        obj_type = obj.get("type")
        obj_id = obj.get("id")
        name = obj.get("name", "")
        revoked = obj.get("revoked", False)
        deprecated = obj.get("x_mitre_deprecated", False)

        if revoked or deprecated:
            continue

        ext_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") in ["mitre-attack", "mitre-enterprise-attack"]:
                ext_id = ref.get("external_id")
                break

        if ext_id:
            obj_id_to_external_id[obj_id] = ext_id
        if name:
            obj_id_to_name[obj_id] = name

        if obj_type == "x-mitre-tactic":
            shortname = obj.get("x_mitre_shortname", "")
            tactic_item = {
                "id": obj_id,
                "external_id": ext_id or "",
                "name": name,
                "shortname": shortname,
                "description": obj.get("description", ""),
                "domain": "enterprise"
            }
            tactics.append(tactic_item)
            if shortname:
                tactic_shortname_to_id[shortname] = ext_id or obj_id

    # Pass 2: Extract techniques and sub-techniques
    # We will identify sub-technique parent relationships from STIX relationships later,
    # but also prepare data structures now.
    subtechnique_objects = []
    technique_objects = []

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        obj_id = obj.get("id")
        ext_id = obj_id_to_external_id.get(obj_id, "")
        is_sub = obj.get("x_mitre_is_subtechnique", False)
        tactic_refs = [kc.get("phase_name") for kc in obj.get("kill_chain_phases", []) if kc.get("kill_chain_name") in ["mitre-attack", "mitre-enterprise-attack"]]
        platforms = obj.get("x_mitre_platforms", [])
        network_requirements = obj.get("x_mitre_network_requirements", False)

        item = {
            "id": obj_id,
            "external_id": ext_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "tactics": tactic_refs,
            "platforms": platforms,
            "is_subtechnique": is_sub,
            "network_requirements": network_requirements,
            "references": [
                {
                    "source_name": ref.get("source_name", ""),
                    "external_id": ref.get("external_id", ""),
                    "url": ref.get("url", "")
                }
                for ref in obj.get("external_references", [])
                if ref.get("url") or ref.get("external_id")
            ]
        }

        if is_sub:
            subtechnique_objects.append(item)
        else:
            technique_objects.append(item)

    # Pass 3: Extract relationships
    parent_map = {}  # sub_technique_id -> parent_external_id

    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        rel_type = obj.get("relationship_type")
        src = obj.get("source_ref")
        tgt = obj.get("target_ref")

        src_ext = obj_id_to_external_id.get(src, src)
        tgt_ext = obj_id_to_external_id.get(tgt, tgt)
        src_name = obj_id_to_name.get(src, "")
        tgt_name = obj_id_to_name.get(tgt, "")

        if rel_type == "subtechnique-of":
            parent_map[src] = {
                "parent_id": tgt,
                "parent_external_id": tgt_ext,
                "parent_name": tgt_name
            }

        relationships.append({
            "id": obj.get("id"),
            "relationship_type": rel_type,
            "source_ref": src,
            "source_external_id": src_ext,
            "source_name": src_name,
            "target_ref": tgt,
            "target_external_id": tgt_ext,
            "target_name": tgt_name,
            "description": obj.get("description", "")
        })

    # Attach parent information to sub-techniques
    for sub in subtechnique_objects:
        pinfo = parent_map.get(sub["id"], {})
        sub["parent_id"] = pinfo.get("parent_id", "")
        sub["parent_external_id"] = pinfo.get("parent_external_id", "")
        sub["parent_name"] = pinfo.get("parent_name", "")

    # Sort outputs
    tactics.sort(key=lambda x: x["external_id"])
    technique_objects.sort(key=lambda x: x["external_id"])
    subtechnique_objects.sort(key=lambda x: x["external_id"])

    # Write processed files
    with open(os.path.join(output_dir, "tactics.json"), "w", encoding="utf-8") as f:
        json.dump(tactics, f, indent=2)

    with open(os.path.join(output_dir, "techniques.json"), "w", encoding="utf-8") as f:
        json.dump(technique_objects, f, indent=2)

    with open(os.path.join(output_dir, "subtechniques.json"), "w", encoding="utf-8") as f:
        json.dump(subtechnique_objects, f, indent=2)

    with open(os.path.join(output_dir, "relationships.json"), "w", encoding="utf-8") as f:
        json.dump(relationships, f, indent=2)

    print(f"Extraction complete:")
    print(f"  Tactics: {len(tactics)} -> tactics.json")
    print(f"  Techniques (Parent): {len(technique_objects)} -> techniques.json")
    print(f"  Sub-techniques: {len(subtechnique_objects)} -> subtechniques.json")
    print(f"  Relationships: {len(relationships)} -> relationships.json")

    # PHASE 6: Curated NEXUS-Forecast Relevance Filter
    all_techs = technique_objects + subtechnique_objects
    
    # Priority network attack keywords / tactics
    curated_knowledge = []
    
    # Priority categories and IDs for network forecasting
    priority_terms = [
        "scanning", "network service", "remote service", "valid account",
        "brute force", "public-facing", "command and control", "application layer protocol",
        "proxy", "ingress tool", "lateral movement", "discovery", "credential access",
        "exfiltration", "data transfer", "traffic", "protocol", "port", "smb", "rdp", "ssh"
    ]
    
    # Critical parent techniques explicitly prioritized
    explicit_priority_ids = {
        "T1595", "T1590", "T1589", "T1592", # Reconnaissance
        "T1190", "T1133", "T1078", "T1200", # Initial Access
        "T1059", "T1203", "T1569", "T1053", # Execution
        "T1046", "T1018", "T1016", "T1040", "T1082", "T1087", "T1069", # Discovery
        "T1110", "T1003", "T1555", "T1552", # Credential Access
        "T1021", "T1570", "T1563", "T1550", # Lateral Movement
        "T1071", "T1090", "T1105", "T1572", "T1573", "T1095", "T1001", # C2
        "T1041", "T1048", "T1567", "T1020", "T1011", "T1052" # Exfiltration
    }

    for t in all_techs:
        ext_id = t["external_id"]
        base_id = ext_id.split(".")[0]
        name_lower = t["name"].lower()
        desc_lower = t["description"].lower()
        tactics_list = t["tactics"]

        # Relevance scoring logic
        is_relevant = False
        relevance_reason = ""

        if base_id in explicit_priority_ids:
            is_relevant = True
            relevance_reason = f"Explicitly identified network attack technique family ({base_id})"
        elif t.get("network_requirements", False):
            is_relevant = True
            relevance_reason = "Technique specifies network requirements in ATT&CK schema"
        elif any(tac in ["reconnaissance", "command-and-control", "exfiltration", "lateral-movement"] for tac in tactics_list):
            if any(term in name_lower or term in desc_lower for term in priority_terms):
                is_relevant = True
                relevance_reason = f"Matches network-observable tactic ({','.join(tactics_list)}) and key behavioral descriptors"

        if is_relevant:
            curated_knowledge.append({
                "attack_id": ext_id,
                "name": t["name"],
                "is_subtechnique": t["is_subtechnique"],
                "parent_id": t.get("parent_external_id", ""),
                "tactics": t["tactics"],
                "platforms": t["platforms"],
                "network_requirements": t.get("network_requirements", False),
                "relevance_reason": relevance_reason,
                "description": t["description"],
                "references": t["references"][:5],
                "source_version": "ATT&CK Enterprise v19.2"
            })

    curated_knowledge.sort(key=lambda x: x["attack_id"])
    nexus_know_path = os.path.join(output_dir, "nexus_forecast_attack_knowledge.json")
    with open(nexus_know_path, "w", encoding="utf-8") as f:
        json.dump(curated_knowledge, f, indent=2)

    print(f"Phase 6 Curated Knowledge: {len(curated_knowledge)} techniques saved to {nexus_know_path}")

    # PHASE 7: Transparent Application-Level Stage Mapping
    # Strictly separates MITRE official tactic from NEXUS-Forecast's application-level stage.
    stage_mapping = []

    # Mapping rules from MITRE tactic / technique behavior to NEXUS-Forecast 9 conceptual stages:
    # BENIGN, RECONNAISSANCE, INITIAL_ACCESS, EXECUTION, DISCOVERY,
    # CREDENTIAL_ACCESS, LATERAL_MOVEMENT, COMMAND_AND_CONTROL, EXFILTRATION
    tactic_to_stage_default = {
        "reconnaissance": ("RECONNAISSANCE", "HIGH", "Direct conceptual alignment with pre-compromise reconnaissance"),
        "initial-access": ("INITIAL_ACCESS", "HIGH", "Direct alignment with network boundary intrusion attempts"),
        "execution": ("EXECUTION", "HIGH", "Direct alignment with malicious binary or script execution phase"),
        "discovery": ("DISCOVERY", "HIGH", "Direct alignment with internal network, port, or host discovery scanning"),
        "credential-access": ("CREDENTIAL_ACCESS", "HIGH", "Direct alignment with authentication probing, brute force, and credential harvesting"),
        "lateral-movement": ("LATERAL_MOVEMENT", "HIGH", "Direct alignment with internal pivot and remote service exploitation"),
        "command-and-control": ("COMMAND_AND_CONTROL", "HIGH", "Direct alignment with outbound beaconing, remote agent tunneling, and C2 interaction"),
        "exfiltration": ("EXFILTRATION", "HIGH", "Direct alignment with unauthorized data staging and outbound transfer"),
    }

    for k in curated_knowledge:
        aid = k["attack_id"]
        tech_name = k["name"]
        primary_tactic = k["tactics"][0] if k["tactics"] else "unknown"

        if primary_tactic in tactic_to_stage_default:
            stage, conf, reason = tactic_to_stage_default[primary_tactic]
        elif len(k["tactics"]) > 1:
            # Multi-tactic ambiguous case: inspect primary or mark review
            matched = False
            for tac in k["tactics"]:
                if tac in tactic_to_stage_default:
                    stage, conf, reason = tactic_to_stage_default[tac]
                    conf = "MEDIUM"
                    reason = f"Multi-tactic technique ({','.join(k['tactics'])}) mapped via active component '{tac}'"
                    matched = True
                    break
            if not matched:
                stage = "UNKNOWN"
                conf = "REVIEW_REQUIRED"
                reason = f"No confident conceptual match for tactics: {','.join(k['tactics'])}"
        else:
            stage = "UNKNOWN"
            conf = "REVIEW_REQUIRED"
            reason = f"Tactic '{primary_tactic}' requires domain specialist review for network stage classification"

        stage_mapping.append({
            "attack_id": aid,
            "technique": tech_name,
            "mitre_tactic": primary_tactic,
            "all_mitre_tactics": k["tactics"],
            "nexus_stage": stage,
            "mapping_confidence": conf,
            "mapping_reason": reason,
            "source": "NEXUS-Forecast Application Mapping v1.0 (Derived from MITRE ATT&CK v19.2)"
        })

    stage_map_path = os.path.join(output_dir, "attack_stage_mapping.json")
    with open(stage_map_path, "w", encoding="utf-8") as f:
        json.dump(stage_mapping, f, indent=2)

    review_req_count = sum(1 for sm in stage_mapping if sm["mapping_confidence"] == "REVIEW_REQUIRED")
    print(f"Phase 7 Stage Mapping: {len(stage_mapping)} mappings saved to {stage_map_path}")
    print(f"  REVIEW_REQUIRED mappings: {review_req_count}")

if __name__ == "__main__":
    extract_mitre_data()
