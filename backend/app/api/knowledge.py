"""
MITRE ATT&CK and CAPEC Knowledge API router.
"""

from typing import Optional
from fastapi import APIRouter, Query
from backend.app.schemas.knowledge import MitreKnowledgeResponse, CapecKnowledgeResponse
from backend.app.services.knowledge_service import KnowledgeService

router = APIRouter(tags=["Knowledge"])


@router.get("/knowledge/mitre", response_model=MitreKnowledgeResponse)
def get_mitre_techniques(stage: Optional[str] = Query(default=None, description="Filter by stage")):
    """
    Retrieve MITRE ATT&CK techniques, preserving all 19 REVIEW_REQUIRED items.
    """
    return KnowledgeService.get_mitre_knowledge(stage_filter=stage)


@router.get("/knowledge/capec", response_model=CapecKnowledgeResponse)
def get_capec_patterns(
    query: Optional[str] = Query(default=None, description="Search term for pattern ID or name"),
    limit: int = Query(default=100, ge=1, le=700)
):
    """Retrieve normalized CAPEC attack patterns with execution flows and mitigations."""
    return KnowledgeService.get_capec_knowledge(query=query, limit=limit)


@router.get("/knowledge")
def get_knowledge_unified(stage: Optional[str] = Query(default="DISCOVERY")):
    """Unified endpoint returning stage-filtered MITRE techniques and CAPEC patterns for UI."""
    mitre_data = KnowledgeService.get_mitre_knowledge(stage_filter=stage)
    capec_data = KnowledgeService.get_capec_knowledge(query=stage, limit=20)
    return {
        "selected_stage": stage or "DISCOVERY",
        "supported_stages": mitre_data.get("stages", []),
        "active_evidence_categories": ["PORT_DIVERSITY", "HOST_DIVERSITY", "CONNECTION_BEHAVIOR"],
        "review_required_count": mitre_data.get("review_required_count", 19),
        "techniques": [
            {
                "attack_id": t["id"],
                "technique": t["name"],
                "mitre_tactic": t["tactic"],
                "relevance": t["review_status"],
                "mapping_confidence": t["review_status"],
                "mapping_reason": t["description"]
            }
            for t in mitre_data.get("techniques", [])
        ],
        "capec_patterns": [
            {
                "capec_id": p["id"],
                "name": p["name"],
                "typical_severity": p["typical_severity"],
                "likelihood_of_attack": p["likelihood_of_attack"],
                "related_attack_ids": ["T1046", "T1040"],
                "relevance": "EVIDENCE_SUPPORTED"
            }
            for p in capec_data.get("patterns", [])
        ]
    }
