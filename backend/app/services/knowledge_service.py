"""
Knowledge Service wrapping Phase 18 MITRE ATT&CK and CAPEC databases.
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional

from backend.app.config import settings

_mitre_mapping: Optional[List[Dict[str, Any]]] = None
_capec_data: Optional[List[Dict[str, Any]]] = None


def load_mitre_data() -> List[Dict[str, Any]]:
    global _mitre_mapping
    if _mitre_mapping is None:
        p = settings.mitre_stage_mapping_path
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                _mitre_mapping = json.load(f)
        else:
            _mitre_mapping = []
    return _mitre_mapping


def load_capec_data() -> List[Dict[str, Any]]:
    global _capec_data
    if _capec_data is None:
        p = settings.capec_path
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                _capec_data = json.load(f)
        else:
            _capec_data = []
    return _capec_data


class KnowledgeService:
    @staticmethod
    def get_mitre_knowledge(stage_filter: Optional[str] = None) -> Dict[str, Any]:
        """Return MITRE ATT&CK techniques, preserving all 19 REVIEW_REQUIRED techniques."""
        raw_list = load_mitre_data()
        
        formatted = []
        for t in raw_list:
            stage = t.get("nexus_stage", t.get("stage", ""))
            if stage_filter and stage_filter.upper() != "ALL":
                if stage.upper() != stage_filter.upper():
                    continue

            conf = t.get("mapping_confidence", "")
            is_review = (conf == "REVIEW_REQUIRED")
            status = "REVIEW_REQUIRED" if is_review else "CONFIRMED"
            
            tid = t.get("attack_id", t.get("technique_id", ""))
            formatted.append({
                "id": tid,
                "name": t.get("technique", t.get("technique_name", "")),
                "tactic": t.get("mitre_tactic", t.get("tactic", "")),
                "stage": stage,
                "review_status": status,
                "url": f"https://attack.mitre.org/techniques/{tid}",
                "description": t.get("mapping_reason", "")
            })

        review_count = sum(1 for t in formatted if t["review_status"] == "REVIEW_REQUIRED")
        stages = sorted(list({t["stage"] for t in formatted if t["stage"]}))

        return {
            "total_techniques": len(formatted),
            "review_required_count": review_count,
            "stages": stages,
            "techniques": formatted
        }

    @staticmethod
    def get_capec_knowledge(query: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
        """Return CAPEC normalized attack patterns."""
        raw_list = load_capec_data()
        
        results = []
        for p in raw_list:
            if not isinstance(p, dict):
                continue
            cid = p.get("capec_id", "")
            name = p.get("name", "")
            abstraction = p.get("abstraction_level", p.get("abstraction", "Standard"))
            likelihood = p.get("likelihood_of_attack", "Medium")
            severity = p.get("typical_severity", "Medium")

            if query:
                q_lower = query.lower()
                if q_lower not in cid.lower() and q_lower not in name.lower():
                    continue

            results.append({
                "id": cid,
                "name": name,
                "abstraction": abstraction,
                "likelihood_of_attack": likelihood,
                "typical_severity": severity,
                "execution_flow": p.get("execution_flow", [])[:5] if isinstance(p.get("execution_flow"), list) else [],
                "mitigations": p.get("mitigations", [])[:5] if isinstance(p.get("mitigations"), list) else []
            })
            if len(results) >= limit:
                break

        return {
            "total_patterns": len(raw_list),
            "filtered_count": len(results),
            "patterns": results
        }
