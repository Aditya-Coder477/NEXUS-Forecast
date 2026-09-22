"""
Attack Stage Explainer and MITRE ATT&CK Contextual Boundary (Phase 17).
Explains predicted macroscopic attack stages using the GRU's stage prediction head.
Enforces the MITRE Contextual Boundary:
- ATT&CK techniques are contextual metadata, NOT proof that a technique occurred.
- Never promotes mapping_confidence 'REVIEW_REQUIRED' without review.
"""

import os
import json
import torch
import numpy as np
from typing import Dict, List, Any, Optional

from src.world_model.dataset import STAGE_VOCABULARY, STAGE_TO_IDX
from src.explainability.integrated_gradients import IntegratedGradientsExplainer
from src.explainability.attribution import AttributionDecomposer


class StageExplainer:
    def __init__(
        self,
        model: torch.nn.Module,
        ig_explainer: IntegratedGradientsExplainer,
        mapping_path: str = "data/knowledge/mitre_attack/processed/attack_stage_mapping.json"
    ):
        self.model = model
        self.ig_explainer = ig_explainer
        self.stage_names = list(STAGE_VOCABULARY)
        self.mitre_mappings = self._load_mitre_mappings(mapping_path)

    def _load_mitre_mappings(self, path: str) -> Dict[str, List[Dict[str, Any]]]:
        """Loads ATT&CK technique mappings grouped by NEXUS macroscopic stage."""
        grouped = {s: [] for s in self.stage_names}
        if not os.path.exists(path):
            return grouped

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for item in data:
            n_stage = item.get("nexus_stage", "").strip().upper()
            if n_stage in grouped:
                grouped[n_stage].append({
                    "attack_id": item.get("attack_id"),
                    "technique": item.get("technique"),
                    "mapping_confidence": item.get("mapping_confidence", "MEDIUM"),
                    "mapping_reason": item.get("mapping_reason", "")
                })

        return grouped

    def explain_predicted_stage(
        self,
        input_tensor: torch.Tensor,
        baseline_tensor: torch.Tensor,
        horizon: int = 1,
        steps: int = 50
    ) -> Dict[str, Any]:
        """
        Explains the predicted attack stage by attributing the GRU stage prediction head.
        """
        if input_tensor.ndim == 2:
            input_tensor = input_tensor.unsqueeze(0)

        # 1. Forward pass to get stage logits and softmax confidence
        with torch.no_grad():
            out = self.model(input_tensor)
            stage_logits = out["stage"][horizon].cpu().numpy()[0] # (9,)
            exp_l = np.exp(stage_logits - np.max(stage_logits))
            stage_probs = exp_l / np.sum(exp_l)
            pred_stage_idx = int(np.argmax(stage_probs))
            pred_stage_name = self.stage_names[pred_stage_idx]
            confidence = float(stage_probs[pred_stage_idx])

        # 2. Compute Integrated Gradients for the predicted stage logit
        ig_res = self.ig_explainer.attribute(
            input_tensor=input_tensor,
            baseline_tensor=baseline_tensor,
            horizon=horizon,
            target_type="stage",
            stage_class=pred_stage_idx,
            steps=steps
        )
        ig_matrix = ig_res["attribution_matrix"]

        # Decompose into feature and temporal attributions
        feat_attrs = AttributionDecomposer.decompose_feature_attribution(ig_matrix)
        time_attrs = AttributionDecomposer.decompose_temporal_attribution(ig_matrix)

        # 3. Retrieve MITRE ATT&CK contextual techniques for this stage
        contextual_techniques = self.mitre_mappings.get(pred_stage_name, [])

        return {
            "predicted_stage": pred_stage_name,
            "stage_id": pred_stage_idx,
            "confidence": round(confidence, 4),
            "stage_probabilities": {
                name: round(float(p), 4) for name, p in zip(self.stage_names, stage_probs)
            },
            "top_stage_supporting_features": feat_attrs[:5],
            "top_stage_influential_timesteps": [t for t in time_attrs if t["raw_attribution"] > 0][:3],
            "mitre_attck_context": {
                "associated_techniques_count": len(contextual_techniques),
                "sample_techniques": contextual_techniques[:4],
                "methodological_boundary": (
                    "Contextual knowledge enrichment only. This model-forecasted stage does NOT prove "
                    "or confirm that any specific MITRE ATT&CK technique occurred in the network traffic."
                )
            }
        }
