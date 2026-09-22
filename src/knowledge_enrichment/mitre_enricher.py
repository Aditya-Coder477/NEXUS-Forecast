"""
MITRE ATT&CK Enrichment Component for NEXUS-Forecast Phase 18.
Loads and indexes authoritative ATT&CK stage mappings and technique details.
Preserves all REVIEW_REQUIRED techniques with zero silent promotions.
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional

from src.knowledge_enrichment.schemas import (
    AttackTechnique,
    KnowledgeRelevance,
    MappingConfidence,
)
from src.knowledge_enrichment.evidence_mapper import EvidenceKnowledgeMapper

logger = logging.getLogger(__name__)

DEFAULT_STAGE_MAPPING_PATH = os.path.join(
    "data", "knowledge", "mitre_attack", "processed", "attack_stage_mapping.json"
)
DEFAULT_TECHNIQUES_PATH = os.path.join(
    "data", "knowledge", "mitre_attack", "processed", "techniques.json"
)


class MitreEnricher:
    """
    Offline enricher for MITRE ATT&CK techniques based on predicted attack stage.
    """

    def __init__(
        self,
        stage_mapping_path: str = DEFAULT_STAGE_MAPPING_PATH,
        techniques_path: str = DEFAULT_TECHNIQUES_PATH,
    ):
        self.stage_mapping_path = stage_mapping_path
        self.techniques_path = techniques_path

        self._stage_to_techniques: Dict[str, List[Dict[str, Any]]] = {}
        self._id_to_mapping: Dict[str, Dict[str, Any]] = {}
        self._id_to_metadata: Dict[str, Dict[str, Any]] = {}
        self._review_required_ids: List[str] = []

        self._load_knowledge()

    def _load_knowledge(self) -> None:
        """Load stage mappings and metadata strictly from local disk."""
        if not os.path.exists(self.stage_mapping_path):
            raise FileNotFoundError(
                f"Authoritative ATT&CK stage mapping file not found at: {self.stage_mapping_path}"
            )

        with open(self.stage_mapping_path, "r", encoding="utf-8") as f:
            mapping_data = json.load(f)

        # Load optional technique metadata (descriptions, platforms)
        if os.path.exists(self.techniques_path):
            with open(self.techniques_path, "r", encoding="utf-8") as f:
                tech_meta_list = json.load(f)
                for item in tech_meta_list:
                    ext_id = item.get("external_id") or item.get("id")
                    if ext_id:
                        self._id_to_metadata[ext_id] = item

        # Index mappings
        for entry in mapping_data:
            att_id = entry.get("attack_id")
            stage = entry.get("nexus_stage")
            conf = entry.get("mapping_confidence", "HIGH")

            if conf == "REVIEW_REQUIRED":
                self._review_required_ids.append(att_id)

            self._id_to_mapping[att_id] = entry
            if stage not in self._stage_to_techniques:
                self._stage_to_techniques[stage] = []
            self._stage_to_techniques[stage].append(entry)

        logger.info(
            f"MitreEnricher initialized: {len(self._id_to_mapping)} techniques mapped across "
            f"{len(self._stage_to_techniques)} stages. "
            f"REVIEW_REQUIRED techniques: {len(self._review_required_ids)}"
        )

    @property
    def review_required_count(self) -> int:
        return len(self._review_required_ids)

    @property
    def review_required_ids(self) -> List[str]:
        return sorted(list(self._review_required_ids))

    def get_stages(self) -> List[str]:
        """Return list of supported macroscopic attack stages."""
        return sorted(list(self._stage_to_techniques.keys()))

    def get_technique_by_id(
        self,
        attack_id: str,
        observed_categories: Optional[List[str]] = None,
    ) -> Optional[AttackTechnique]:
        """Lookup a specific ATT&CK technique by its identifier (e.g. T1046)."""
        entry = self._id_to_mapping.get(attack_id)
        if not entry:
            return None

        meta = self._id_to_metadata.get(attack_id, {})
        observed_cats = observed_categories or []
        is_review = (entry.get("mapping_confidence") == "REVIEW_REQUIRED")

        relevance, matched_cats, notes = EvidenceKnowledgeMapper.evaluate_technique_relevance(
            attack_id=attack_id,
            is_review_required=is_review,
            observed_categories=observed_cats,
        )

        return AttackTechnique(
            attack_id=entry["attack_id"],
            technique=entry.get("technique", meta.get("name", "")),
            nexus_stage=entry.get("nexus_stage", ""),
            mitre_tactic=entry.get("mitre_tactic", ""),
            all_mitre_tactics=entry.get("all_mitre_tactics", []),
            mapping_confidence=entry.get("mapping_confidence", "HIGH"),
            mapping_reason=entry.get("mapping_reason", ""),
            source=entry.get("source", ""),
            description=meta.get("description", ""),
            platforms=meta.get("platforms", []),
            relevance=relevance,
            supporting_evidence_categories=matched_cats,
            evidence_notes=notes,
        )

    def get_techniques_for_stage(
        self,
        stage: str,
        observed_categories: Optional[List[str]] = None,
        max_techniques: Optional[int] = None,
    ) -> List[AttackTechnique]:
        """
        Return mapped ATT&CK techniques for a predicted attack stage,
        ranked by relevance (EVIDENCE_SUPPORTED first, then CONTEXTUALLY_RELEVANT, then REVIEW_REQUIRED).
        """
        raw_entries = self._stage_to_techniques.get(stage, [])
        if not raw_entries:
            return []

        observed_cats = observed_categories or []
        results: List[AttackTechnique] = []

        for entry in raw_entries:
            att_id = entry["attack_id"]
            meta = self._id_to_metadata.get(att_id, {})
            is_review = (entry.get("mapping_confidence") == "REVIEW_REQUIRED")

            relevance, matched_cats, notes = EvidenceKnowledgeMapper.evaluate_technique_relevance(
                attack_id=att_id,
                is_review_required=is_review,
                observed_categories=observed_cats,
            )

            tech = AttackTechnique(
                attack_id=att_id,
                technique=entry.get("technique", meta.get("name", "")),
                nexus_stage=entry.get("nexus_stage", ""),
                mitre_tactic=entry.get("mitre_tactic", ""),
                all_mitre_tactics=entry.get("all_mitre_tactics", []),
                mapping_confidence=entry.get("mapping_confidence", "HIGH"),
                mapping_reason=entry.get("mapping_reason", ""),
                source=entry.get("source", ""),
                description=meta.get("description", ""),
                platforms=meta.get("platforms", []),
                relevance=relevance,
                supporting_evidence_categories=matched_cats,
                evidence_notes=notes,
            )
            results.append(tech)

        # Sort order: EVIDENCE_SUPPORTED (0), CONTEXTUALLY_RELEVANT (1), REVIEW_REQUIRED (2)
        rank_order = {
            KnowledgeRelevance.EVIDENCE_SUPPORTED.value: 0,
            KnowledgeRelevance.CONTEXTUALLY_RELEVANT.value: 1,
            KnowledgeRelevance.REVIEW_REQUIRED.value: 2,
            KnowledgeRelevance.NOT_RELEVANT.value: 3,
        }
        results.sort(key=lambda t: (rank_order.get(t.relevance, 9), t.attack_id))

        if max_techniques is not None and max_techniques > 0:
            return results[:max_techniques]
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Return summary metrics on loaded ATT&CK mapping."""
        stage_counts = {s: len(entries) for s, entries in self._stage_to_techniques.items()}
        return {
            "total_mapped_techniques": len(self._id_to_mapping),
            "stages_count": len(self._stage_to_techniques),
            "techniques_per_stage": stage_counts,
            "review_required_count": len(self._review_required_ids),
            "review_required_ids": self.review_required_ids,
        }
