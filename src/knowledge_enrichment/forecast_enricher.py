"""
Master Forecast Enrichment Coordinator for NEXUS-Forecast Phase 18.
Combines GRU multi-step rollout forecasts, probability calibration, attack stages,
Phase 17 model attributions, and evidence categories to produce enriched forecast objects.
"""

import os
import json
import uuid
import datetime
import pandas as pd
from typing import Dict, List, Any, Optional

from src.knowledge_enrichment.schemas import (
    EnrichedHorizonForecast,
    EnrichedForecastResult,
    AttackTechnique,
    CapecPattern,
    KnowledgeRelevance,
)
from src.knowledge_enrichment.mitre_enricher import MitreEnricher
from src.knowledge_enrichment.capec_enricher import CapecEnricher
from src.knowledge_enrichment.evidence_mapper import EvidenceKnowledgeMapper


class ForecastEnricher:
    """
    Enriches temporal forecasts with MITRE ATT&CK techniques and CAPEC patterns.
    """

    def __init__(
        self,
        mitre_enricher: Optional[MitreEnricher] = None,
        capec_enricher: Optional[CapecEnricher] = None,
    ):
        self.mitre_enricher = mitre_enricher or MitreEnricher()
        self.capec_enricher = capec_enricher or CapecEnricher()

    def enrich_horizon(
        self,
        horizon_step: int,
        horizon_seconds: int,
        predicted_attack: bool,
        calibrated_attack_prob: float,
        predicted_stage: str,
        stage_confidence: float,
        top_features: Optional[List[str]] = None,
        observed_categories: Optional[List[str]] = None,
        max_techniques: int = 10,
        max_patterns: int = 10,
    ) -> EnrichedHorizonForecast:
        """
        Enrich a single horizon prediction.
        """
        # Resolve evidence categories
        categories = list(observed_categories or [])
        if top_features and not categories:
            categories = EvidenceKnowledgeMapper.map_features_to_categories(top_features)

        # If benign or no attack predicted, return empty knowledge collections
        if not predicted_attack or predicted_stage.upper() in ["BENIGN", "NONE"]:
            return EnrichedHorizonForecast(
                horizon_step=horizon_step,
                horizon_seconds=horizon_seconds,
                predicted_attack=predicted_attack,
                calibrated_attack_prob=float(calibrated_attack_prob),
                predicted_stage=predicted_stage,
                stage_confidence=float(stage_confidence),
                top_evidence_categories=categories,
                attack_techniques=[],
                capec_patterns=[],
                unresolved_review_items=[],
            )

        # Retrieve mapped techniques
        techniques = self.mitre_enricher.get_techniques_for_stage(
            stage=predicted_stage,
            observed_categories=categories,
            max_techniques=max_techniques,
        )

        # Retrieve cross-referenced CAPEC patterns
        patterns = self.capec_enricher.get_patterns_for_techniques(
            attack_techniques=techniques,
            observed_categories=categories,
            max_patterns=max_patterns,
        )

        # Extract any unresolved review items
        review_items = [
            f"{t.attack_id} ({t.technique})"
            for t in techniques
            if t.relevance == KnowledgeRelevance.REVIEW_REQUIRED.value
        ]

        return EnrichedHorizonForecast(
            horizon_step=horizon_step,
            horizon_seconds=horizon_seconds,
            predicted_attack=predicted_attack,
            calibrated_attack_prob=float(calibrated_attack_prob),
            predicted_stage=predicted_stage,
            stage_confidence=float(stage_confidence),
            top_evidence_categories=categories,
            attack_techniques=techniques,
            capec_patterns=patterns,
            unresolved_review_items=review_items,
        )

    def enrich_rollout_result(
        self,
        rollout_data: Dict[str, Any],
        explanation_data: Optional[Dict[str, Any]] = None,
        forecast_id: Optional[str] = None,
        origin_window_index: int = 0,
        max_techniques_per_horizon: int = 8,
        max_patterns_per_horizon: int = 8,
    ) -> EnrichedForecastResult:
        """
        Enrich a multi-step rollout forecast dictionary.
        """
        fid = forecast_id or f"NEXUS-FC-{uuid.uuid4().hex[:8].upper()}"
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Extract top features from explanation if provided
        top_feats = []
        if explanation_data:
            top_feats = explanation_data.get("top_features", [])

        categories = EvidenceKnowledgeMapper.map_features_to_categories(top_feats)

        horizons_dict: Dict[str, EnrichedHorizonForecast] = {}
        has_any_attack = False
        trajectory = []

        raw_horizons = rollout_data.get("horizons", {})
        # Support format where rollout_data itself has keys "h1", "h3", "h6" or "step_1", etc.
        if not raw_horizons:
            raw_horizons = {k: v for k, v in rollout_data.items() if k.startswith("h") or k.startswith("step")}

        for h_key, h_info in raw_horizons.items():
            step = h_info.get("step") or h_info.get("horizon_step", 1)
            secs = h_info.get("seconds") or h_info.get("horizon_seconds", step * 30)
            is_attack = bool(h_info.get("attack_decision", h_info.get("predicted_attack", False)))
            prob = float(h_info.get("calibrated_probability", h_info.get("calibrated_attack_prob", 0.0)))
            stage = str(h_info.get("predicted_stage", "BENIGN"))
            stage_conf = float(h_info.get("stage_confidence", 1.0))

            if is_attack:
                has_any_attack = True
            trajectory.append(stage)

            enriched_h = self.enrich_horizon(
                horizon_step=step,
                horizon_seconds=secs,
                predicted_attack=is_attack,
                calibrated_attack_prob=prob,
                predicted_stage=stage,
                stage_confidence=stage_conf,
                top_features=top_feats,
                observed_categories=categories,
                max_techniques=max_techniques_per_horizon,
                max_patterns=max_patterns_per_horizon,
            )
            horizons_dict[h_key] = enriched_h

        summary = {
            "overall_attack_forecasted": has_any_attack,
            "predicted_trajectory": trajectory,
            "origin_window_index": origin_window_index,
            "total_horizons": len(horizons_dict),
            "evidence_categories_detected": categories,
        }

        meta = {
            "version": "1.0.0",
            "phase": "PHASE_18",
            "mitre_attack_version": "v19.2",
            "capec_version": "v3.9",
            "model_architecture": "GRU_WORLD_MODEL",
            "threshold": 0.45,
        }

        return EnrichedForecastResult(
            forecast_id=fid,
            timestamp=ts,
            origin_window_index=origin_window_index,
            horizons=horizons_dict,
            summary=summary,
            meta=meta,
        )

    def generate_stage_knowledge_matrix_dataframe(self) -> pd.DataFrame:
        """
        Generate a comprehensive stage-to-attack-capec matrix DataFrame across all stages.
        """
        records = []
        stages = self.mitre_enricher.get_stages()

        for stage in stages:
            techniques = self.mitre_enricher.get_techniques_for_stage(stage)
            patterns = self.capec_enricher.get_patterns_for_techniques(techniques)
            pattern_map = {p.capec_id: p for p in patterns}

            for tech in techniques:
                # Find linked CAPECs
                linked_capec_ids = []
                for p_id, p_obj in pattern_map.items():
                    if tech.attack_id in p_obj.related_attack_ids or tech.attack_id.split(".")[0] in p_obj.related_attack_ids:
                        linked_capec_ids.append(f"{p_obj.capec_id} ({p_obj.name})")

                capec_str = "; ".join(linked_capec_ids) if linked_capec_ids else "None Mapped"

                records.append({
                    "nexus_stage": stage,
                    "attack_id": tech.attack_id,
                    "technique_name": tech.technique,
                    "mitre_tactic": tech.mitre_tactic,
                    "mapping_confidence": tech.mapping_confidence,
                    "review_required": (tech.mapping_confidence == "REVIEW_REQUIRED"),
                    "mapping_reason": tech.mapping_reason,
                    "linked_capec_patterns": capec_str,
                })

        return pd.DataFrame(records)

    @staticmethod
    def to_soc_markdown(result: EnrichedForecastResult) -> str:
        """
        Format an EnrichedForecastResult as an actionable SOC intelligence report.
        """
        md = []
        md.append(f"# NEXUS-Forecast SOC Intelligence Report: {result.forecast_id}")
        md.append(f"**Timestamp**: `{result.timestamp}` | **Origin Window Index**: `{result.origin_window_index}`")
        md.append(f"**Overall Threat Status**: `{'ATTACK FORECASTED' if result.summary.get('overall_attack_forecasted') else 'BENIGN / NORMAL'}`")
        md.append(f"**Forecast Trajectory**: `{' -> '.join(result.summary.get('predicted_trajectory', []))}`")
        md.append(f"**Active Evidence Categories**: `{', '.join(result.summary.get('evidence_categories_detected', [])) or 'None'}`\n")

        md.append("---")
        md.append("## Horizon Breakdown & MITRE ATT&CK / CAPEC Mapping\n")

        for h_key, h_data in result.horizons.items():
            md.append(f"### Horizon {h_key.upper()} (Step +{h_data.horizon_step} / +{h_data.horizon_seconds}s)")
            status_str = "**ATTACK**" if h_data.predicted_attack else "**BENIGN**"
            md.append(f"- **Prediction**: {status_str} (Calibrated Probability: **{h_data.calibrated_attack_prob:.2%}**)")
            md.append(f"- **Predicted Stage**: `{h_data.predicted_stage}` (Stage Confidence: **{h_data.stage_confidence:.2%}**)")

            if not h_data.predicted_attack:
                md.append("- *No attack behaviors anticipated in this window.*\n")
                continue

            # List ATT&CK Techniques
            md.append("\n#### Contextually Relevant & Evidence-Supported ATT&CK Techniques:")
            if not h_data.attack_techniques:
                md.append("*(No specific techniques mapped to this stage)*")
            else:
                md.append("| ATT&CK ID | Technique Name | Relevance Tier | Confidence | Evidence Notes |")
                md.append("| :--- | :--- | :--- | :--- | :--- |")
                for t in h_data.attack_techniques:
                    rel_badge = f"**{t.relevance}**" if t.relevance == "EVIDENCE_SUPPORTED" else t.relevance
                    md.append(f"| `{t.attack_id}` | {t.technique} | {rel_badge} | `{t.mapping_confidence}` | {t.evidence_notes} |")

            # List CAPEC Patterns
            md.append("\n#### Associated CAPEC Attack Patterns:")
            if not h_data.capec_patterns:
                md.append("*(No associated CAPEC patterns identified)*")
            else:
                md.append("| CAPEC ID | Pattern Name | Severity | Relevance | Likelihood |")
                md.append("| :--- | :--- | :--- | :--- | :--- |")
                for c in h_data.capec_patterns:
                    rel_badge = f"**{c.relevance}**" if c.relevance == "EVIDENCE_SUPPORTED" else c.relevance
                    md.append(f"| `{c.capec_id}` | {c.name} | `{c.typical_severity}` | {rel_badge} | `{c.likelihood_of_attack}` |")

            # Highlight Review Required Items
            if h_data.unresolved_review_items:
                md.append("\n> [!WARNING]")
                md.append(f"> **Techniques Requiring SOC Analyst Review ({len(h_data.unresolved_review_items)})**:")
                for r in h_data.unresolved_review_items:
                    md.append(f"> - `{r}`")
            md.append("\n")

        md.append("---")
        md.append("### Epistemic Boundary Notice")
        md.append(
            "> [!NOTE]\n"
            "> All MITRE ATT&CK techniques and CAPEC patterns surfaced above represent structured contextual "
            "knowledge associations derived from macroscopic network telemetry and sequence modeling. "
            "They do **not** constitute definitive forensic proof of malicious execution or endpoint compromise."
        )

        return "\n".join(md)
