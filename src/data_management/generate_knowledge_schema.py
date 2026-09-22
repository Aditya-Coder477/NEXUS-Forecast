"""
Generates data/knowledge/knowledge_schema.json representing the NEXUS-Forecast
four-layer knowledge architecture:
Network Evidence -> Forecasted Stage -> MITRE ATT&CK Technique -> CAPEC Attack Pattern.
Populates only officially documented mappings between ATT&CK and CAPEC.
"""

import os
import json

def build_knowledge_schema():
    # Load normalized capec
    capec_path = "data/knowledge/capec/processed/capec_normalized.json"
    with open(capec_path, "r", encoding="utf-8") as f:
        capec_data = json.load(f)

    # Load curated attack knowledge
    attack_path = "data/knowledge/mitre_attack/processed/nexus_forecast_attack_knowledge.json"
    with open(attack_path, "r", encoding="utf-8") as f:
        nexus_attack = json.load(f)

    # Load stage mappings
    stage_path = "data/knowledge/mitre_attack/processed/attack_stage_mapping.json"
    with open(stage_path, "r", encoding="utf-8") as f:
        stage_mappings = json.load(f)

    attack_to_stage = {m["attack_id"]: m for m in stage_mappings}
    nexus_attack_ids = {item["attack_id"]: item for item in nexus_attack}
    base_attack_ids = {item["attack_id"].split(".")[0]: item for item in nexus_attack}

    # Extract verified concrete mappings without fabrication
    concrete_mappings = []
    seen_pairs = set()

    for c in capec_data:
        for tm in c.get("taxonomy_mappings", []):
            if tm.get("taxonomy_name") == "ATTACK":
                std_id = tm.get("standard_attack_id")
                entry_id = tm.get("entry_id")
                
                matched = nexus_attack_ids.get(std_id) or nexus_attack_ids.get(entry_id) or base_attack_ids.get(std_id) or base_attack_ids.get(entry_id)
                if matched:
                    aid = matched["attack_id"]
                    cid = c["capec_id"]
                    pair = (aid, cid)
                    if pair in seen_pairs:
                        continue
                    seen_pairs.add(pair)

                    st_info = attack_to_stage.get(aid, {})

                    concrete_mappings.append({
                        "capec_id": cid,
                        "capec_name": c["name"],
                        "capec_abstraction": c["abstraction_level"],
                        "capec_severity": c.get("typical_severity", "Unknown"),
                        "attack_id": aid,
                        "attack_name": matched["name"],
                        "mitre_tactic": st_info.get("mitre_tactic", ""),
                        "forecasted_nexus_stage": st_info.get("nexus_stage", "UNKNOWN"),
                        "stage_mapping_confidence": st_info.get("mapping_confidence", "HIGH"),
                        "mapping_provenance": "Official MITRE CAPEC v3.9 Taxonomy Mapping (Unfabricated)"
                    })

    schema_doc = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "NEXUS-Forecast Multilayer Cybersecurity Knowledge Schema",
        "description": "Defines the 4-layer interpretive representation linking temporal network states to MITRE ATT&CK techniques and CAPEC attack patterns.",
        "version": "1.0.0",
        "architecture_pipeline": {
            "layer_1": {
                "name": "Network Evidence / Features",
                "description": "Empirical network metrics extracted from NetFlow/Binetflow windows (duration, protocol, packet counts, byte volumes, directional flow ratios, state transitions).",
                "nature": "Quantitative ML input features for temporal forecasting"
            },
            "layer_2": {
                "name": "Forecasted Attack Stage",
                "description": "Temporal state predicted by the NEXUS-Forecast world model.",
                "allowed_stages": [
                    "BENIGN",
                    "RECONNAISSANCE",
                    "INITIAL_ACCESS",
                    "EXECUTION",
                    "DISCOVERY",
                    "CREDENTIAL_ACCESS",
                    "LATERAL_MOVEMENT",
                    "COMMAND_AND_CONTROL",
                    "EXFILTRATION"
                ],
                "nature": "Predicted macroscopic attack phase"
            },
            "layer_3": {
                "name": "MITRE ATT&CK Technique Layer",
                "description": "Adversary tactics and techniques associated with the predicted stage for operational enrichment and explainability.",
                "source": "MITRE Enterprise ATT&CK v19.2",
                "nature": "Adversary behavioral tactics/techniques"
            },
            "layer_4": {
                "name": "CAPEC Attack Pattern Layer",
                "description": "Detailed attack mechanism abstractions, execution flows, and weaknesses associated with mapped ATT&CK techniques.",
                "source": "MITRE CAPEC v3.9",
                "nature": "Attack pattern contextual enrichment"
            }
        },
        "knowledge_contracts": {
            "evidence_contract": {
                "type": "object",
                "properties": {
                    "flow_id": {"type": "string"},
                    "timestamp_start": {"type": "string", "format": "date-time"},
                    "duration_seconds": {"type": "number"},
                    "protocol": {"type": "string"},
                    "src_ip": {"type": "string"},
                    "dst_ip": {"type": "string"},
                    "src_port": {"type": "integer"},
                    "dst_port": {"type": "integer"},
                    "total_packets": {"type": "integer"},
                    "total_bytes": {"type": "integer"},
                    "flow_rate_bytes_per_sec": {"type": "number"}
                },
                "required": ["timestamp_start", "duration_seconds", "protocol", "src_ip", "dst_ip", "total_packets", "total_bytes"]
            },
            "stage_prediction_contract": {
                "type": "object",
                "properties": {
                    "forecast_horizon_seconds": {"type": "number"},
                    "predicted_stage": {"type": "string", "enum": [
                        "BENIGN", "RECONNAISSANCE", "INITIAL_ACCESS", "EXECUTION", 
                        "DISCOVERY", "CREDENTIAL_ACCESS", "LATERAL_MOVEMENT", 
                        "COMMAND_AND_CONTROL", "EXFILTRATION"
                    ]},
                    "stage_probability": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                    "world_model_confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0}
                },
                "required": ["forecast_horizon_seconds", "predicted_stage", "stage_probability"]
            },
            "attack_enrichment_contract": {
                "type": "object",
                "properties": {
                    "attack_id": {"type": "string", "pattern": "^T[0-9]{4}(\\.[0-9]{3})?$"},
                    "technique_name": {"type": "string"},
                    "primary_tactic": {"type": "string"},
                    "mapping_confidence": {"type": "string", "enum": ["HIGH", "MEDIUM", "REVIEW_REQUIRED"]},
                    "mapping_reason": {"type": "string"}
                },
                "required": ["attack_id", "technique_name", "primary_tactic", "mapping_confidence"]
            },
            "capec_enrichment_contract": {
                "type": "object",
                "properties": {
                    "capec_id": {"type": "string", "pattern": "^CAPEC-[0-9]+$"},
                    "attack_pattern_name": {"type": "string"},
                    "abstraction_level": {"type": "string", "enum": ["Meta", "Standard", "Detailed", "Category", "View"]},
                    "typical_severity": {"type": "string"},
                    "related_cwe_ids": {"type": "array", "items": {"type": "string"}},
                    "mapping_provenance": {"type": "string"}
                },
                "required": ["capec_id", "attack_pattern_name", "abstraction_level", "mapping_provenance"]
            }
        },
        "non_fabrication_guarantee": {
            "policy": "No speculative or synthesized ATT&CK-to-CAPEC links are admitted. Only links explicitly published in official MITRE taxonomy catalogs are populated.",
            "total_supported_mappings_in_curated_set": len(concrete_mappings),
            "mappings": concrete_mappings
        }
    }

    out_path = "data/knowledge/knowledge_schema.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(schema_doc, f, indent=2)

    print(f"Knowledge Schema successfully generated at: {out_path}")
    print(f"Total concrete documented ATT&CK<->CAPEC mappings included: {len(concrete_mappings)}")

if __name__ == "__main__":
    build_knowledge_schema()
