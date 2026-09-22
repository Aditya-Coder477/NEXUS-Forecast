"""
Offline-First Knowledge Loader for NEXUS-Forecast.

Provides fast, deterministic, in-memory lookups for MITRE ATT&CK and CAPEC
without requiring runtime network access or external APIs.
Guarantees SIH competition readiness in offline/air-gapped evaluation environments.
"""

import os
import json
from typing import Dict, List, Optional, Any

class NexusKnowledgeBase:
    def __init__(self, base_dir: str = "data/knowledge"):
        self.base_dir = base_dir
        self.mitre_dir = os.path.join(base_dir, "mitre_attack", "processed")
        self.capec_dir = os.path.join(base_dir, "capec", "processed")
        self.schema_path = os.path.join(base_dir, "knowledge_schema.json")

        # In-memory indexes
        self.tactics: Dict[str, Dict[str, Any]] = {}
        self.techniques: Dict[str, Dict[str, Any]] = {}
        self.subtechniques: Dict[str, Dict[str, Any]] = {}
        self.curated_knowledge: Dict[str, Dict[str, Any]] = {}
        self.stage_mappings: Dict[str, Dict[str, Any]] = {}
        self.stage_to_techniques: Dict[str, List[str]] = {}
        self.capec_patterns: Dict[str, Dict[str, Any]] = {}
        self.attack_to_capec: Dict[str, List[Dict[str, Any]]] = {}

        self.loaded = False
        self.load_all()

    def load_all(self):
        """Loads all knowledge assets deterministically from local files."""
        # 1. Tactics
        tactics_file = os.path.join(self.mitre_dir, "tactics.json")
        if os.path.exists(tactics_file):
            with open(tactics_file, "r", encoding="utf-8") as f:
                for t in json.load(f):
                    self.tactics[t.get("external_id") or t.get("id")] = t

        # 2. Parent Techniques
        tech_file = os.path.join(self.mitre_dir, "techniques.json")
        if os.path.exists(tech_file):
            with open(tech_file, "r", encoding="utf-8") as f:
                for t in json.load(f):
                    self.techniques[t.get("external_id") or t.get("id")] = t

        # 3. Sub-techniques
        sub_file = os.path.join(self.mitre_dir, "subtechniques.json")
        if os.path.exists(sub_file):
            with open(sub_file, "r", encoding="utf-8") as f:
                for t in json.load(f):
                    self.subtechniques[t.get("external_id") or t.get("id")] = t

        # 4. Curated NEXUS Knowledge
        curated_file = os.path.join(self.mitre_dir, "nexus_forecast_attack_knowledge.json")
        if os.path.exists(curated_file):
            with open(curated_file, "r", encoding="utf-8") as f:
                for k in json.load(f):
                    self.curated_knowledge[k["attack_id"]] = k

        # 5. Stage Mappings
        stage_file = os.path.join(self.mitre_dir, "attack_stage_mapping.json")
        if os.path.exists(stage_file):
            with open(stage_file, "r", encoding="utf-8") as f:
                for sm in json.load(f):
                    aid = sm["attack_id"]
                    self.stage_mappings[aid] = sm
                    stage = sm["nexus_stage"]
                    if stage not in self.stage_to_techniques:
                        self.stage_to_techniques[stage] = []
                    self.stage_to_techniques[stage].append(aid)

        # 6. CAPEC Patterns
        capec_file = os.path.join(self.capec_dir, "capec_normalized.json")
        if os.path.exists(capec_file):
            with open(capec_file, "r", encoding="utf-8") as f:
                for cp in json.load(f):
                    self.capec_patterns[cp["capec_id"]] = cp

        # 7. Concrete ATT&CK <-> CAPEC Mappings from Schema
        if os.path.exists(self.schema_path):
            with open(self.schema_path, "r", encoding="utf-8") as f:
                schema_data = json.load(f)
                mappings = schema_data.get("non_fabrication_guarantee", {}).get("mappings", [])
                for m in mappings:
                    aid = m["attack_id"]
                    if aid not in self.attack_to_capec:
                        self.attack_to_capec[aid] = []
                    self.attack_to_capec[aid].append(m)

        self.loaded = True

    def get_stage_explanation(self, attack_id: str) -> Optional[Dict[str, Any]]:
        return self.stage_mappings.get(attack_id)

    def get_techniques_for_stage(self, stage: str) -> List[Dict[str, Any]]:
        tech_ids = self.stage_to_techniques.get(stage.upper(), [])
        results = []
        for tid in tech_ids:
            item = self.curated_knowledge.get(tid) or self.techniques.get(tid) or self.subtechniques.get(tid)
            if item:
                results.append(item)
        return results

    def get_capec_for_technique(self, attack_id: str) -> List[Dict[str, Any]]:
        return self.attack_to_capec.get(attack_id, [])

    def get_capec_pattern(self, capec_id: str) -> Optional[Dict[str, Any]]:
        return self.capec_patterns.get(capec_id)

    def get_summary_stats(self) -> Dict[str, int]:
        return {
            "tactics": len(self.tactics),
            "techniques": len(self.techniques),
            "subtechniques": len(self.subtechniques),
            "curated_nexus_techniques": len(self.curated_knowledge),
            "stage_mappings": len(self.stage_mappings),
            "capec_patterns": len(self.capec_patterns),
            "techniques_with_capec_links": len(self.attack_to_capec)
        }
