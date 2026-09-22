"""
CAPEC Attack Pattern Enrichment Component for NEXUS-Forecast Phase 18.
Loads and indexes normalized CAPEC patterns, linking them to ATT&CK techniques
and network flow evidence without external network calls.
"""

import os
import json
import logging
from typing import Dict, List, Set, Any, Optional

from src.knowledge_enrichment.schemas import (
    CapecPattern,
    KnowledgeRelevance,
    AttackTechnique,
)
from src.knowledge_enrichment.evidence_mapper import EvidenceKnowledgeMapper

logger = logging.getLogger(__name__)

DEFAULT_CAPEC_PATH = os.path.join(
    "data", "knowledge", "capec", "processed", "capec_normalized.json"
)


class CapecEnricher:
    """
    Offline enricher for MITRE CAPEC attack patterns linked to predicted attack stages and techniques.
    """

    def __init__(self, capec_path: str = DEFAULT_CAPEC_PATH):
        self.capec_path = capec_path

        self._patterns_by_id: Dict[str, Dict[str, Any]] = {}
        self._patterns_by_attack_id: Dict[str, List[str]] = {}

        self._load_knowledge()

    @staticmethod
    def normalize_attack_id(entry_id: str) -> str:
        """Ensure ATT&CK technique IDs start with standard 'T' prefix."""
        entry_id = str(entry_id).strip()
        if not entry_id.startswith("T") and entry_id:
            return f"T{entry_id}"
        return entry_id

    def _load_knowledge(self) -> None:
        """Load CAPEC patterns strictly from local disk."""
        if not os.path.exists(self.capec_path):
            raise FileNotFoundError(
                f"Authoritative CAPEC normalized file not found at: {self.capec_path}"
            )

        with open(self.capec_path, "r", encoding="utf-8") as f:
            patterns_data = json.load(f)

        for pat in patterns_data:
            c_id = pat.get("capec_id")
            if not c_id:
                continue

            self._patterns_by_id[c_id] = pat

            # Index by linked ATT&CK ID
            for tax in pat.get("taxonomy_mappings", []):
                if tax.get("taxonomy_name") == "ATTACK":
                    raw_att = tax.get("entry_id")
                    if raw_att:
                        norm_att = self.normalize_attack_id(raw_att)
                        if norm_att not in self._patterns_by_attack_id:
                            self._patterns_by_attack_id[norm_att] = []
                        if c_id not in self._patterns_by_attack_id[norm_att]:
                            self._patterns_by_attack_id[norm_att].append(c_id)

                        # Also index base ID if subtechnique
                        if "." in norm_att:
                            base_att = norm_att.split(".")[0]
                            if base_att not in self._patterns_by_attack_id:
                                self._patterns_by_attack_id[base_att] = []
                            if c_id not in self._patterns_by_attack_id[base_att]:
                                self._patterns_by_attack_id[base_att].append(c_id)

        logger.info(
            f"CapecEnricher initialized: {len(self._patterns_by_id)} patterns loaded. "
            f"{len(self._patterns_by_attack_id)} ATT&CK techniques cross-referenced."
        )

    def get_pattern_by_id(
        self,
        capec_id: str,
        observed_categories: Optional[List[str]] = None,
        attack_relevance_map: Optional[Dict[str, str]] = None,
    ) -> Optional[CapecPattern]:
        """Lookup a specific CAPEC pattern by identifier (e.g. CAPEC-287)."""
        pat = self._patterns_by_id.get(capec_id)
        if not pat:
            return None

        # Extract linked ATT&CK IDs
        related_attacks = []
        for tax in pat.get("taxonomy_mappings", []):
            if tax.get("taxonomy_name") == "ATTACK":
                eid = tax.get("entry_id")
                if eid:
                    related_attacks.append(self.normalize_attack_id(eid))

        observed_cats = observed_categories or []
        att_rel_map = attack_relevance_map or {}

        relevance, matched_cats, notes = EvidenceKnowledgeMapper.evaluate_capec_relevance(
            capec_id=capec_id,
            related_attack_ids=related_attacks,
            observed_categories=observed_cats,
            attack_relevance_map=att_rel_map,
        )

        return CapecPattern(
            capec_id=pat.get("capec_id", capec_id),
            numeric_id=pat.get("numeric_id", 0),
            name=pat.get("name", ""),
            abstraction_level=pat.get("abstraction_level", "Standard"),
            status=pat.get("status", "Stable"),
            description=pat.get("description", ""),
            typical_severity=pat.get("typical_severity", "Medium") or "Medium",
            likelihood_of_attack=pat.get("likelihood_of_attack", "Medium") or "Medium",
            prerequisites=pat.get("prerequisites", []),
            consequences=pat.get("consequences", []),
            related_attack_ids=related_attacks,
            relevance=relevance,
            supporting_evidence_categories=matched_cats,
            evidence_notes=notes,
        )

    def get_patterns_for_techniques(
        self,
        attack_techniques: List[AttackTechnique],
        observed_categories: Optional[List[str]] = None,
        max_patterns: Optional[int] = None,
    ) -> List[CapecPattern]:
        """
        Return CAPEC patterns cross-referenced by the supplied ATT&CK techniques,
        ranked by relevance (EVIDENCE_SUPPORTED first, then CONTEXTUALLY_RELEVANT, then REVIEW_REQUIRED).
        """
        if not attack_techniques:
            return []

        observed_cats = observed_categories or []
        att_rel_map = {t.attack_id: t.relevance for t in attack_techniques}

        seen_capec_ids: Set[str] = set()
        results: List[CapecPattern] = []

        for tech in attack_techniques:
            c_ids = self._patterns_by_attack_id.get(tech.attack_id, [])
            # Also check base ID
            if "." in tech.attack_id:
                base_id = tech.attack_id.split(".")[0]
                for cid in self._patterns_by_attack_id.get(base_id, []):
                    if cid not in c_ids:
                        c_ids.append(cid)

            for cid in c_ids:
                if cid in seen_capec_ids:
                    continue
                seen_capec_ids.add(cid)

                pat_obj = self.get_pattern_by_id(
                    capec_id=cid,
                    observed_categories=observed_cats,
                    attack_relevance_map=att_rel_map,
                )
                if pat_obj:
                    results.append(pat_obj)

        # Sort order: EVIDENCE_SUPPORTED (0), CONTEXTUALLY_RELEVANT (1), REVIEW_REQUIRED (2)
        rank_order = {
            KnowledgeRelevance.EVIDENCE_SUPPORTED.value: 0,
            KnowledgeRelevance.CONTEXTUALLY_RELEVANT.value: 1,
            KnowledgeRelevance.REVIEW_REQUIRED.value: 2,
            KnowledgeRelevance.NOT_RELEVANT.value: 3,
        }
        results.sort(key=lambda p: (rank_order.get(p.relevance, 9), p.numeric_id))

        if max_patterns is not None and max_patterns > 0:
            return results[:max_patterns]
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Return summary metrics on loaded CAPEC database."""
        return {
            "total_patterns": len(self._patterns_by_id),
            "attack_cross_references_count": len(self._patterns_by_attack_id),
        }
