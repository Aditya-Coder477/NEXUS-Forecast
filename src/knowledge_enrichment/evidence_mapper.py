"""
Deterministic Evidence-to-Knowledge Compatibility Rules.
Maps network features and Phase 17 evidence categories to MITRE ATT&CK techniques
and CAPEC patterns without invoking external services or statistical estimation.
"""

from typing import Dict, List, Set, Any, Optional
from src.knowledge_enrichment.schemas import EvidenceCategory, KnowledgeRelevance

# Direct mapping between evidence categories and relevant ATT&CK technique IDs
CATEGORY_TO_ATTACK_IDS: Dict[str, Set[str]] = {
    EvidenceCategory.PORT_DIVERSITY.value: {
        "T1046", "T1595.001", "T1595.002", "T1040"
    },
    EvidenceCategory.HOST_DIVERSITY.value: {
        "T1018", "T1046", "T1021", "T1021.001", "T1021.002", "T1021.004", "T1072", "T1091"
    },
    EvidenceCategory.TRAFFIC_VOLUME.value: {
        "T1498", "T1498.001", "T1499", "T1499.004", "T1048", "T1048.003", "T1020", "T1001.001"
    },
    EvidenceCategory.CONNECTION_BEHAVIOR.value: {
        "T1046", "T1498.001", "T1499.002", "T1071", "T1001", "T1205", "T1205.001"
    },
    EvidenceCategory.DIRECTIONALITY.value: {
        "T1041", "T1048", "T1048.002", "T1048.003", "T1020", "T1071", "T1071.001"
    },
    EvidenceCategory.PROTOCOL_BEHAVIOR.value: {
        "T1071", "T1071.001", "T1071.002", "T1071.003", "T1071.004", "T1095", "T1001"
    },
    EvidenceCategory.TEMPORAL_PERSISTENCE.value: {
        "T1071", "T1053", "T1053.002", "T1053.003", "T1053.005", "T1001"
    }
}

# Direct mapping between evidence categories and relevant CAPEC pattern IDs
CATEGORY_TO_CAPEC_IDS: Dict[str, Set[str]] = {
    EvidenceCategory.PORT_DIVERSITY.value: {
        "CAPEC-287", "CAPEC-300", "CAPEC-303", "CAPEC-304", "CAPEC-305"
    },
    EvidenceCategory.HOST_DIVERSITY.value: {
        "CAPEC-292", "CAPEC-118", "CAPEC-309", "CAPEC-563"
    },
    EvidenceCategory.TRAFFIC_VOLUME.value: {
        "CAPEC-488", "CAPEC-486", "CAPEC-482", "CAPEC-147", "CAPEC-166", "CAPEC-130"
    },
    EvidenceCategory.CONNECTION_BEHAVIOR.value: {
        "CAPEC-482", "CAPEC-287", "CAPEC-487", "CAPEC-125"
    },
    EvidenceCategory.DIRECTIONALITY.value: {
        "CAPEC-166", "CAPEC-219", "CAPEC-117"
    },
    EvidenceCategory.PROTOCOL_BEHAVIOR.value: {
        "CAPEC-272", "CAPEC-311", "CAPEC-216"
    },
    EvidenceCategory.TEMPORAL_PERSISTENCE.value: {
        "CAPEC-594", "CAPEC-595"
    }
}

# Mapping of individual canonical network features (22 features) to evidence category
FEATURE_TO_CATEGORY: Dict[str, str] = {
    "total_flows": EvidenceCategory.TRAFFIC_VOLUME.value,
    "unique_src_hosts": EvidenceCategory.HOST_DIVERSITY.value,
    "unique_dst_hosts": EvidenceCategory.HOST_DIVERSITY.value,
    "unique_dst_ports": EvidenceCategory.PORT_DIVERSITY.value,
    "unique_protocols": EvidenceCategory.PROTOCOL_BEHAVIOR.value,
    "total_packets": EvidenceCategory.TRAFFIC_VOLUME.value,
    "total_bytes": EvidenceCategory.TRAFFIC_VOLUME.value,
    "inbound_bytes": EvidenceCategory.DIRECTIONALITY.value,
    "outbound_bytes": EvidenceCategory.DIRECTIONALITY.value,
    "inbound_outbound_ratio": EvidenceCategory.DIRECTIONALITY.value,
    "mean_flow_duration": EvidenceCategory.CONNECTION_BEHAVIOR.value,
    "mean_packet_rate": EvidenceCategory.TRAFFIC_VOLUME.value,
    "mean_byte_rate": EvidenceCategory.TRAFFIC_VOLUME.value,
    "mean_iat": EvidenceCategory.CONNECTION_BEHAVIOR.value,
    "std_iat": EvidenceCategory.CONNECTION_BEHAVIOR.value,
    "syn_count": EvidenceCategory.CONNECTION_BEHAVIOR.value,
    "ack_count": EvidenceCategory.CONNECTION_BEHAVIOR.value,
    "rst_count": EvidenceCategory.CONNECTION_BEHAVIOR.value,
    "fin_count": EvidenceCategory.CONNECTION_BEHAVIOR.value,
    "connection_failure_rate": EvidenceCategory.CONNECTION_BEHAVIOR.value,
    "unique_host_pair_count": EvidenceCategory.HOST_DIVERSITY.value,
    "fan_out_ratio": EvidenceCategory.HOST_DIVERSITY.value,
}


class EvidenceKnowledgeMapper:
    """
    Evaluates evidence support for ATT&CK techniques and CAPEC patterns.
    """

    @staticmethod
    def map_features_to_categories(feature_names: List[str]) -> List[str]:
        """Convert a list of high-attribution feature names into unique evidence categories."""
        cats = set()
        for feat in feature_names:
            cat = FEATURE_TO_CATEGORY.get(feat)
            if cat:
                cats.add(cat)
        return sorted(list(cats))

    @classmethod
    def evaluate_technique_relevance(
        cls,
        attack_id: str,
        is_review_required: bool,
        observed_categories: List[str],
    ) -> (str, List[str], str):
        """
        Determine relevance tier and evidence notes for an ATT&CK technique.
        Returns: (relevance_string, matched_categories, notes)
        """
        if is_review_required:
            return (
                KnowledgeRelevance.REVIEW_REQUIRED.value,
                [],
                "Manual SOC analyst review required due to ambiguous or multi-tactic classification."
            )

        # Base ID without subtechnique for category lookup
        base_id = attack_id.split(".")[0]
        matched_cats = []

        for cat in observed_categories:
            supported_ids = CATEGORY_TO_ATTACK_IDS.get(cat, set())
            if attack_id in supported_ids or base_id in supported_ids:
                matched_cats.append(cat)

        if matched_cats:
            return (
                KnowledgeRelevance.EVIDENCE_SUPPORTED.value,
                matched_cats,
                f"Supported by observed network evidence in: {', '.join(matched_cats)}."
            )
        else:
            return (
                KnowledgeRelevance.CONTEXTUALLY_RELEVANT.value,
                [],
                "Contextually aligned with predicted attack stage, but no direct matching category anomaly."
            )

    @classmethod
    def evaluate_capec_relevance(
        cls,
        capec_id: str,
        related_attack_ids: List[str],
        observed_categories: List[str],
        attack_relevance_map: Dict[str, str],
    ) -> (str, List[str], str):
        """
        Determine relevance tier and evidence notes for a CAPEC pattern.
        Returns: (relevance_string, matched_categories, notes)
        """
        matched_cats = []
        for cat in observed_categories:
            supported_capecs = CATEGORY_TO_CAPEC_IDS.get(cat, set())
            if capec_id in supported_capecs:
                matched_cats.append(cat)

        # Check if any associated ATT&CK technique is evidence supported
        has_supported_technique = any(
            attack_relevance_map.get(att_id) == KnowledgeRelevance.EVIDENCE_SUPPORTED.value
            for att_id in related_attack_ids
        )

        has_review_technique = any(
            attack_relevance_map.get(att_id) == KnowledgeRelevance.REVIEW_REQUIRED.value
            for att_id in related_attack_ids
        )

        if matched_cats or has_supported_technique:
            return (
                KnowledgeRelevance.EVIDENCE_SUPPORTED.value,
                matched_cats,
                f"Attack pattern supported by evidence category match or linked technique evidence."
            )
        elif has_review_technique:
            return (
                KnowledgeRelevance.REVIEW_REQUIRED.value,
                [],
                "Linked to an ATT&CK technique marked for SOC review."
            )
        else:
            return (
                KnowledgeRelevance.CONTEXTUALLY_RELEVANT.value,
                [],
                "Contextually relevant attack pattern based on predicted attack stage."
            )
