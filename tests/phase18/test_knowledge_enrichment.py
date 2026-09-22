"""
Unit tests for Phase 18: ATT&CK and CAPEC Forecast Enrichment.
Verifies all mapping rules, offline execution, evidence categorization,
and strict preservation of the 19 REVIEW_REQUIRED techniques.
"""

import os
import json
import pytest
import pandas as pd
import socket

from src.knowledge_enrichment.schemas import (
    KnowledgeRelevance,
    MappingConfidence,
    EvidenceCategory,
    AttackTechnique,
    CapecPattern,
    EnrichedHorizonForecast,
    EnrichedForecastResult,
)
from src.knowledge_enrichment.mitre_enricher import MitreEnricher
from src.knowledge_enrichment.capec_enricher import CapecEnricher
from src.knowledge_enrichment.evidence_mapper import EvidenceKnowledgeMapper
from src.knowledge_enrichment.forecast_enricher import ForecastEnricher


@pytest.fixture(scope="module")
def mitre_enricher():
    return MitreEnricher()


@pytest.fixture(scope="module")
def capec_enricher():
    return CapecEnricher()


@pytest.fixture(scope="module")
def forecast_enricher(mitre_enricher, capec_enricher):
    return ForecastEnricher(mitre_enricher, capec_enricher)


# 1. MITRE Enricher Tests
def test_mitre_enricher_load_count(mitre_enricher):
    stats = mitre_enricher.get_statistics()
    assert stats["total_mapped_techniques"] == 210, f"Expected 210 techniques, got {stats['total_mapped_techniques']}"
    assert stats["stages_count"] == 8, f"Expected 8 stages, got {stats['stages_count']}"


def test_mitre_review_required_count(mitre_enricher):
    assert mitre_enricher.review_required_count == 19, (
        f"Expected exactly 19 REVIEW_REQUIRED techniques, got {mitre_enricher.review_required_count}"
    )


def test_mitre_review_required_preserved_ids(mitre_enricher):
    expected_sample = ["T1040", "T1053", "T1078", "T1133", "T1205", "T1659"]
    actual_ids = mitre_enricher.review_required_ids
    for exp_id in expected_sample:
        assert exp_id in actual_ids, f"Expected review-required technique {exp_id} to be preserved"


def test_mitre_stage_filtering(mitre_enricher):
    recon_techs = mitre_enricher.get_techniques_for_stage("RECONNAISSANCE")
    assert len(recon_techs) > 0
    for t in recon_techs:
        assert t.nexus_stage == "RECONNAISSANCE"
        assert t.attack_id.startswith("T")


def test_mitre_get_technique_by_id(mitre_enricher):
    tech = mitre_enricher.get_technique_by_id("T1046")
    assert tech is not None
    assert tech.attack_id == "T1046"
    assert "Network Service" in tech.technique or "Scan" in tech.technique or "Discovery" in tech.technique


# 2. CAPEC Enricher Tests
def test_capec_enricher_load_count(capec_enricher):
    stats = capec_enricher.get_statistics()
    assert stats["total_patterns"] == 615, f"Expected 615 patterns, got {stats['total_patterns']}"
    assert stats["attack_cross_references_count"] > 0


def test_capec_attack_cross_references(capec_enricher):
    # Test normalization and lookup of T1046
    patterns = capec_enricher.get_patterns_for_techniques(
        [AttackTechnique(attack_id="T1046", technique="Network Service Discovery", nexus_stage="DISCOVERY", mitre_tactic="discovery")]
    )
    assert len(patterns) > 0
    capec_ids = [p.capec_id for p in patterns]
    # Should include CAPEC-287 or CAPEC-300
    assert any("287" in cid or "300" in cid for cid in capec_ids)


def test_capec_pattern_by_id(capec_enricher):
    pat = capec_enricher.get_pattern_by_id("CAPEC-287")
    assert pat is not None
    assert pat.capec_id == "CAPEC-287"
    assert "Port" in pat.name or "Scan" in pat.name
    assert len(pat.prerequisites) > 0 or len(pat.consequences) > 0


# 3. Evidence Mapping Tests
def test_evidence_mapper_feature_to_category():
    features = ["unique_dst_ports", "total_packets", "syn_count", "outbound_bytes"]
    cats = EvidenceKnowledgeMapper.map_features_to_categories(features)
    assert EvidenceCategory.PORT_DIVERSITY.value in cats
    assert EvidenceCategory.TRAFFIC_VOLUME.value in cats
    assert EvidenceCategory.CONNECTION_BEHAVIOR.value in cats
    assert EvidenceCategory.DIRECTIONALITY.value in cats


def test_evidence_upgrade_to_evidence_supported(mitre_enricher):
    # T1046 without evidence
    tech_no_ev = mitre_enricher.get_technique_by_id("T1046", observed_categories=[])
    assert tech_no_ev.relevance == KnowledgeRelevance.CONTEXTUALLY_RELEVANT.value

    # T1046 with PORT_DIVERSITY evidence
    tech_with_ev = mitre_enricher.get_technique_by_id(
        "T1046", observed_categories=[EvidenceCategory.PORT_DIVERSITY.value]
    )
    assert tech_with_ev.relevance == KnowledgeRelevance.EVIDENCE_SUPPORTED.value
    assert EvidenceCategory.PORT_DIVERSITY.value in tech_with_ev.supporting_evidence_categories


def test_review_required_not_promoted(mitre_enricher):
    # T1040 is REVIEW_REQUIRED; even with PORT_DIVERSITY it MUST remain REVIEW_REQUIRED
    tech = mitre_enricher.get_technique_by_id(
        "T1040", observed_categories=[EvidenceCategory.PORT_DIVERSITY.value, EvidenceCategory.HOST_DIVERSITY.value]
    )
    assert tech is not None
    assert tech.relevance == KnowledgeRelevance.REVIEW_REQUIRED.value
    assert tech.mapping_confidence == "REVIEW_REQUIRED"


# 4. Forecast Enrichment Coordinator Tests
def test_benign_forecast_enrichment(forecast_enricher):
    res = forecast_enricher.enrich_horizon(
        horizon_step=1,
        horizon_seconds=30,
        predicted_attack=False,
        calibrated_attack_prob=0.03,
        predicted_stage="BENIGN",
        stage_confidence=0.99,
    )
    assert res.predicted_attack is False
    assert len(res.attack_techniques) == 0
    assert len(res.capec_patterns) == 0


def test_forecast_enricher_single_horizon(forecast_enricher):
    res = forecast_enricher.enrich_horizon(
        horizon_step=1,
        horizon_seconds=30,
        predicted_attack=True,
        calibrated_attack_prob=0.85,
        predicted_stage="RECONNAISSANCE",
        stage_confidence=0.92,
        top_features=["unique_dst_ports"],
    )
    assert res.predicted_attack is True
    assert len(res.attack_techniques) > 0
    assert any(t.relevance == KnowledgeRelevance.EVIDENCE_SUPPORTED.value for t in res.attack_techniques)


def test_forecast_enricher_multi_horizon_rollout(forecast_enricher):
    rollout_data = {
        "h1": {"step": 1, "seconds": 30, "attack_decision": True, "calibrated_probability": 0.88, "predicted_stage": "RECONNAISSANCE", "stage_confidence": 0.90},
        "h3": {"step": 3, "seconds": 90, "attack_decision": True, "calibrated_probability": 0.92, "predicted_stage": "DISCOVERY", "stage_confidence": 0.85},
    }
    res = forecast_enricher.enrich_rollout_result(
        rollout_data=rollout_data,
        explanation_data={"top_features": ["unique_dst_ports", "unique_dst_hosts"]},
        forecast_id="TEST-ROLLOUT-001"
    )
    assert res.forecast_id == "TEST-ROLLOUT-001"
    assert "h1" in res.horizons
    assert "h3" in res.horizons
    assert res.summary["overall_attack_forecasted"] is True
    assert res.summary["predicted_trajectory"] == ["RECONNAISSANCE", "DISCOVERY"]


def test_stage_knowledge_matrix_dataframe(forecast_enricher):
    df = forecast_enricher.generate_stage_knowledge_matrix_dataframe()
    assert isinstance(df, pd.DataFrame)
    assert len(df) == 210
    required_cols = {"nexus_stage", "attack_id", "technique_name", "mitre_tactic", "mapping_confidence", "linked_capec_patterns"}
    assert required_cols.issubset(set(df.columns))
    # Verify review required count in dataframe
    assert df["review_required"].sum() == 19


def test_soc_markdown_generation(forecast_enricher):
    rollout_data = {
        "h1": {"step": 1, "seconds": 30, "attack_decision": True, "calibrated_probability": 0.95, "predicted_stage": "COMMAND_AND_CONTROL", "stage_confidence": 0.91}
    }
    res = forecast_enricher.enrich_rollout_result(
        rollout_data=rollout_data,
        explanation_data={"top_features": ["outbound_bytes"]},
        forecast_id="TEST-SOC-001"
    )
    md = forecast_enricher.to_soc_markdown(res)
    assert "# NEXUS-Forecast SOC Intelligence Report" in md
    assert "TEST-SOC-001" in md
    assert "COMMAND_AND_CONTROL" in md
    assert "Epistemic Boundary Notice" in md


def test_offline_guarantee(monkeypatch):
    """Verify that execution cannot make network socket connections."""
    def guarded_socket(*args, **kwargs):
        raise RuntimeError("Illegal attempt to open a network socket in offline air-gapped environment!")

    monkeypatch.setattr(socket, "socket", guarded_socket)

    # Perform enricher operations under socket guard
    mitre = MitreEnricher()
    capec = CapecEnricher()
    fe = ForecastEnricher(mitre, capec)
    techs = mitre.get_techniques_for_stage("INITIAL_ACCESS")
    assert len(techs) > 0
    pats = capec.get_patterns_for_techniques(techs)
    assert len(pats) > 0
