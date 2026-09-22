"""
Human-Readable SOC Explanation Generator and Machine-Readable JSON Schema Formatter (Phase 17).
Generates:
1. Machine-readable JSON explanation objects conforming to Phase 17 schema (Section 27).
2. Analyst-ready SOC narrative answering WHY, WHEN, WHAT EVIDENCE, and HOW SENSITIVE (Section 23 & 28).
"""

import json
from typing import Dict, List, Any, Optional

LIMITATIONS_LIST = [
    "Attribution reflects model decision mechanics, not physical attack causality.",
    "Correlated network-state features can distribute attribution across multiple dimensions.",
    "Aggregated temporal states summarize flow dynamics; attribution does not point to a single packet.",
    "Baseline selection (benign training median) establishes the mathematical reference point.",
    "Counterfactual perturbations measure model sensitivity, not simulated real-world attack mitigation.",
    "MITRE ATT&CK techniques are contextual enrichments, not proof that a specific exploit occurred."
]


class HumanExplanationGenerator:
    @staticmethod
    def build_machine_explanation(
        metadata: Dict[str, Any],
        forecast_info: Dict[str, Any],
        top_features: List[Dict[str, Any]],
        temporal_attribution: List[Dict[str, Any]],
        feature_time_matrix: List[List[float]],
        evidence_dict: Dict[str, Any],
        counterfactual_list: List[Dict[str, Any]],
        temporal_ablation_list: List[Dict[str, Any]],
        stage_explanation: Dict[str, Any],
        ground_truth: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Constructs the machine-readable explanation schema complying with Section 27.
        """
        return {
            "prediction_origin": metadata.get("prediction_origin", "Unknown"),
            "dataset": metadata.get("dataset", "Unknown"),
            "scenario_id": metadata.get("scenario_id", "Unknown"),
            "forecast_horizon_seconds": forecast_info.get("horizon_seconds", 30),
            "raw_attack_probability": round(float(forecast_info.get("raw_probability", 0.0)), 4),
            "calibrated_attack_probability": round(float(forecast_info.get("calibrated_probability", 0.0)), 4),
            "operational_threshold": float(forecast_info.get("threshold", 0.45)),
            "forecast_decision": forecast_info.get("decision", "BENIGN_FORECAST"),
            "predicted_stage": stage_explanation.get("predicted_stage", "Benign"),
            "stage_confidence": round(float(stage_explanation.get("confidence", 0.0)), 4),
            "explanation": {
                "method": "integrated_gradients",
                "integration_steps": 50,
                "baseline": "benign_training_median",
                "top_features": top_features,
                "temporal_attribution": temporal_attribution,
                "feature_time_attribution": feature_time_matrix
            },
            "evidence": evidence_dict,
            "counterfactual": {
                "feature_sensitivity": counterfactual_list,
                "temporal_ablation": temporal_ablation_list
            },
            "stage_explanation": stage_explanation,
            "ground_truth": ground_truth,
            "limitations": LIMITATIONS_LIST
        }

    @staticmethod
    def render_soc_narrative(explanation_obj: Dict[str, Any]) -> str:
        """
        Renders a concise, human-readable SOC analyst report answering:
        WHY, WHEN, WHAT EVIDENCE, and HOW SENSITIVE.
        """
        h_sec = explanation_obj["forecast_horizon_seconds"]
        cal_p = explanation_obj["calibrated_attack_probability"]
        th = explanation_obj["operational_threshold"]
        decision = explanation_obj["forecast_decision"]
        stage = explanation_obj["predicted_stage"]
        conf = explanation_obj["stage_confidence"]
        dataset = explanation_obj["dataset"]
        scenario = explanation_obj["scenario_id"]
        ts = explanation_obj["prediction_origin"]

        top_feats = explanation_obj["explanation"]["top_features"][:4]
        top_times = [t for t in explanation_obj["explanation"]["temporal_attribution"] if t["raw_attribution"] > 0][:3]
        if not top_times:
            top_times = explanation_obj["explanation"]["temporal_attribution"][-2:]

        sensitivities = explanation_obj["counterfactual"]["feature_sensitivity"][:3]
        observations = explanation_obj["evidence"].get("supporting_observations", [])

        lines = [
            "=" * 60,
            "NEXUS-FORECAST — FORECAST EXPLANATION REPORT",
            "=" * 60,
            f"Dataset:            {dataset}",
            f"Scenario:           {scenario}",
            f"Prediction Origin:  {ts}",
            f"Forecast Horizon:   +{h_sec} seconds",
            f"Attack Probability: {cal_p:.4f} (Calibrated)",
            f"Decision Threshold: {th:.2f}",
            f"Forecast Decision:  {decision}",
            f"Predicted Stage:    {stage} (Confidence: {conf:.2%})",
            "-" * 60,
            "WHY? — TOP CONTRIBUTING NETWORK-STATE FEATURES",
            "-" * 60
        ]

        for idx, f in enumerate(top_feats, start=1):
            name = f["feature"]
            attr = f["raw_attribution"]
            dir_txt = f["direction"]
            norm_imp = f["normalized_importance"]
            lines.append(f"{idx}. {name}")
            lines.append(f"   Attribution:  {attr:+.4f} ({dir_txt}, relative importance: {norm_imp:.1%})")

        lines.extend([
            "-" * 60,
            "WHEN? — MOST INFLUENTIAL HISTORICAL WINDOWS",
            "-" * 60
        ])
        for idx, t in enumerate(top_times, start=1):
            pos = t["relative_position"]
            attr = t["raw_attribution"]
            dir_txt = t["direction"]
            lines.append(f"{idx}. {pos} | Attribution: {attr:+.4f} ({dir_txt})")

        lines.extend([
            "-" * 60,
            "WHAT EVIDENCE? — OBSERVED NETWORK BEHAVIOR & DEVIATIONS",
            "-" * 60
        ])
        if observations:
            for obs in observations[:3]:
                lines.append(f"• {obs['observation_text']}")
        else:
            lines.append("• Traffic features within expected baseline bounds during recent observation windows.")

        lines.extend([
            "-" * 60,
            "HOW SENSITIVE? — MODEL SENSITIVITY UNDER PERTURBATION",
            "-" * 60
        ])
        for sens in sensitivities:
            feat = sens["feature"]
            orig_p = sens["original_calibrated_probability"]
            pert_p = sens["perturbed_calibrated_probability"]
            delta_p = sens["delta_calibrated_probability"]
            lines.append(f"• Feature: {feat}")
            lines.append(f"  Calibrated Probability shift when set to benign baseline: {orig_p:.4f} -> {pert_p:.4f} (Delta: {delta_p:+.4f})")

        mitre_ctx = explanation_obj.get("stage_explanation", {}).get("mitre_attck_context", {})
        samples = mitre_ctx.get("sample_techniques", [])
        if samples:
            lines.extend([
                "-" * 60,
                "KNOWLEDGE CONTEXT — OPTIONAL MITRE ATT&CK TECHNIQUES",
                "-" * 60,
                f"Contextual mapping for macroscopic stage [{stage}]:"
            ])
            for t in samples[:3]:
                lines.append(f"• {t.get('attack_id')}: {t.get('technique')} (Confidence: {t.get('mapping_confidence')})")
            lines.append("Note: This is contextual enrichment, not proof that these techniques occurred in traffic.")

        lines.extend([
            "-" * 60,
            "ANALYST INTERPRETATION & LIMITATIONS",
            "-" * 60,
            "The forecast is driven by specific multi-window deviations from benign baseline traffic.",
            "This explanation describes model attribution and supporting network observations.",
            "It does not establish attacker intent, physical proof, or causal certainty.",
            "=" * 60
        ])

        return "\n".join(lines)
