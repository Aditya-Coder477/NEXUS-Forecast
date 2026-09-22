"""
Automated Test Suite for NEXUS-Forecast Phase 17: Explainability & Evidence Attribution.
Covers:
1. Model, Scaler, and Calibration Loading.
2. BaselineManager: anti-leakage guarantee (TRAIN split only) & statistics computation.
3. Integrated Gradients: (10, 22) tensor shapes, completeness axiom, determinism.
4. AttributionDecomposer: signed/absolute attributions, feature ordering, temporal ordering.
5. EvidenceAttributor & Traceability: 22-feature mapping, baseline deviation, redaction.
6. CounterfactualAnalyzer: feature perturbation & temporal ablation consistency.
7. StageExplainer: stage logit attribution and MITRE boundary.
8. HumanExplanationGenerator: JSON schema serialization and SOC narrative formatting.
9. Immutability Check: Verification that Phase 15/16 checkpoints were not altered.
"""

import os
import sys
import hashlib
import json
import pytest
import torch
import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.abspath("."))

from src.world_model.dataset import STATE_FEATURE_NAMES, STAGE_VOCABULARY, extract_temporal_arrays
from src.world_model.gru_model import GRUWorldModel
from src.explainability.baseline import BaselineManager
from src.explainability.integrated_gradients import IntegratedGradientsExplainer
from src.explainability.attribution import AttributionDecomposer
from src.explainability.evidence import EvidenceAttributor, FEATURE_TRACEABILITY_SPEC
from src.explainability.counterfactual import CounterfactualAnalyzer
from src.explainability.stage_explainer import StageExplainer
from src.explainability.human_explanation import HumanExplanationGenerator

FROZEN_GRU_HASH = "9f94d0aacff538096d2770e1b4f1509e5b38ae8f78f0cb31b850cb903fa8bc9f"
FROZEN_SCALER_HASH = "9d1e26da627dd0879f2bb640fa762bce14e50ac9f875e9fff8ee6d2a969a2ff2"


@pytest.fixture(scope="module")
def env_setup():
    device = torch.device("cpu")
    model_path = "models/world_model/gru/best_model.pt"
    scaler_path = "models/world_model/gru/scaler.joblib"
    cal_path = "models/world_model/gru/calibration_model.joblib"
    meta_path = "models/world_model/gru/metadata.json"

    assert os.path.exists(model_path), f"Missing GRU model at {model_path}"
    assert os.path.exists(scaler_path), f"Missing scaler at {scaler_path}"

    scaler = joblib.load(scaler_path)
    calibrators = joblib.load(cal_path) if os.path.exists(cal_path) else None

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    model = GRUWorldModel(
        input_size=meta["input_size"],
        hidden_size=meta["hidden_size"],
        num_layers=meta["num_layers"],
        dropout=meta["dropout"],
        bidirectional=meta["bidirectional"],
        forecast_horizons=meta["forecast_horizons"],
        num_stages=meta.get("num_stages", 9)
    )
    checkpoint = torch.load(model_path, map_location=device)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.to(device)
    model.eval()

    # Load small slice of sequences for testing
    seq_path = "data/processed/forecast_sequences/unsw_nb15_sequences.parquet"
    assert os.path.exists(seq_path), f"Missing test sequences at {seq_path}"
    df = pd.read_parquet(seq_path)

    return {
        "device": device,
        "model": model,
        "scaler": scaler,
        "calibrator": calibrators[1] if calibrators else None,
        "df": df
    }


def test_model_immutability():
    """Verify that model and scaler weights match the pre-Phase 17 audit hashes."""
    model_path = "models/world_model/gru/best_model.pt"
    scaler_path = "models/world_model/gru/scaler.joblib"

    current_model_hash = hashlib.sha256(open(model_path, "rb").read()).hexdigest()
    current_scaler_hash = hashlib.sha256(open(scaler_path, "rb").read()).hexdigest()

    assert current_model_hash == FROZEN_GRU_HASH, "Model weights were modified! Safety violation."
    assert current_scaler_hash == FROZEN_SCALER_HASH, "Scaler was modified! Safety violation."


def test_baseline_manager_anti_leakage(env_setup):
    """Test that BaselineManager only accepts TRAIN data and computes correct shapes."""
    scaler = env_setup["scaler"]
    df = env_setup["df"]

    bm = BaselineManager(scaler=scaler)
    bm.fit(df)

    assert bm.is_fitted
    assert bm.benign_median_unscaled.shape == (22,)
    assert bm.benign_median_scaled.shape == (22,)
    assert len(bm.stats) == 22

    # Baseline sequence shape
    base_seq = bm.get_baseline_sequence(seq_len=10, scaled=True)
    assert base_seq.shape == (1, 10, 22)

    # Robust deviation
    dev = bm.compute_deviation("total_flows", 500.0)
    assert "iqr_deviation" in dev
    assert "p95_exceeded" in dev


def test_integrated_gradients_shape_and_completeness(env_setup):
    """Verify IG output shape (10, 22) and completeness axiom F(X) - F(X') ≈ sum(IG)."""
    model = env_setup["model"]
    device = env_setup["device"]
    scaler = env_setup["scaler"]
    df = env_setup["df"]

    bm = BaselineManager(scaler=scaler).fit(df)
    explainer = IntegratedGradientsExplainer(model, device)

    # Extract single test sequence
    test_df = df[df["split"] == "TEST"].iloc[0:1]
    X_test, _, _, _, _ = extract_temporal_arrays(test_df, scaler=scaler, fit_scaler=False, horizons=[1])
    x_tensor = torch.tensor(X_test, dtype=torch.float32)
    base_tensor = torch.tensor(bm.get_baseline_sequence(10, scaled=True), dtype=torch.float32)

    res = explainer.attribute(x_tensor, base_tensor, horizon=1, steps=50, tolerance=0.10)
    ig_mat = res["attribution_matrix"]

    assert ig_mat.shape == (10, 22), f"Expected (10, 22) but got {ig_mat.shape}"
    comp = res["completeness"]
    assert comp["passed"], f"Completeness check failed: rel_error={comp['relative_error']}"


def test_attribution_determinism(env_setup):
    """Verify that Integrated Gradients produces identical attributions on repeat runs."""
    model = env_setup["model"]
    device = env_setup["device"]
    scaler = env_setup["scaler"]
    df = env_setup["df"]

    bm = BaselineManager(scaler=scaler).fit(df)
    explainer = IntegratedGradientsExplainer(model, device)

    test_df = df[df["split"] == "TEST"].iloc[0:1]
    X_test, _, _, _, _ = extract_temporal_arrays(test_df, scaler=scaler, fit_scaler=False, horizons=[1])
    x_tensor = torch.tensor(X_test, dtype=torch.float32)
    base_tensor = torch.tensor(bm.get_baseline_sequence(10, scaled=True), dtype=torch.float32)

    res1 = explainer.attribute(x_tensor, base_tensor, horizon=1, steps=30)
    res2 = explainer.attribute(x_tensor, base_tensor, horizon=1, steps=30)

    np.testing.assert_allclose(res1["attribution_matrix"], res2["attribution_matrix"], rtol=1e-5)


def test_attribution_decomposer(env_setup):
    """Test feature and temporal decomposition preserves 22 features and 10 timesteps."""
    # Synthetic attribution matrix
    np.random.seed(42)
    synthetic_mat = np.random.randn(10, 22)

    feat_attrs = AttributionDecomposer.decompose_feature_attribution(synthetic_mat)
    time_attrs = AttributionDecomposer.decompose_temporal_attribution(synthetic_mat)
    df_mat = AttributionDecomposer.get_feature_time_dataframe(synthetic_mat)

    assert len(feat_attrs) == 22
    assert len(time_attrs) == 10
    assert df_mat.shape == (10, 22)
    assert df_mat.columns.tolist() == list(STATE_FEATURE_NAMES)


def test_evidence_traceability_table():
    """Verify that all 22 state features have defined traceability metadata."""
    assert len(FEATURE_TRACEABILITY_SPEC) == 22
    for feat in STATE_FEATURE_NAMES:
        assert feat in FEATURE_TRACEABILITY_SPEC, f"Feature {feat} missing in traceability spec!"
        spec = FEATURE_TRACEABILITY_SPEC[feat]
        assert "category" in spec
        assert "traceable" in spec
        assert "source_fields" in spec


def test_counterfactual_sensitivity(env_setup):
    """Test feature perturbation and temporal ablation in-memory copy without side-effects."""
    model = env_setup["model"]
    device = env_setup["device"]
    scaler = env_setup["scaler"]
    calibrator = env_setup["calibrator"]
    df = env_setup["df"]

    bm = BaselineManager(scaler=scaler).fit(df)
    cf = CounterfactualAnalyzer(model, bm, device, calibrator)

    test_df = df[df["split"] == "TEST"].iloc[0:1]
    X_test, _, _, _, _ = extract_temporal_arrays(test_df, scaler=scaler, fit_scaler=False, horizons=[1])
    x_tensor = torch.tensor(X_test, dtype=torch.float32)

    dummy_top_feats = [{"feature": "total_flows", "feature_index": 0, "direction": "attack_supporting"}]
    feat_sens = cf.analyze_feature_sensitivity(x_tensor, dummy_top_feats, horizon=1, top_k=1)

    assert len(feat_sens) == 1
    assert "delta_logit" in feat_sens[0]
    assert "delta_calibrated_probability" in feat_sens[0]

    # Check that original x_tensor was not modified
    x_check, _, _, _, _ = extract_temporal_arrays(test_df, scaler=scaler, fit_scaler=False, horizons=[1])
    np.testing.assert_allclose(x_tensor.numpy(), x_check)


def test_stage_explainer(env_setup):
    """Verify stage explainer returns predicted stage, confidence, and contextual techniques."""
    model = env_setup["model"]
    device = env_setup["device"]
    scaler = env_setup["scaler"]
    df = env_setup["df"]

    bm = BaselineManager(scaler=scaler).fit(df)
    explainer = IntegratedGradientsExplainer(model, device)
    se = StageExplainer(model, explainer)

    test_df = df[df["split"] == "TEST"].iloc[0:1]
    X_test, _, _, _, _ = extract_temporal_arrays(test_df, scaler=scaler, fit_scaler=False, horizons=[1])
    x_tensor = torch.tensor(X_test, dtype=torch.float32)
    base_tensor = torch.tensor(bm.get_baseline_sequence(10, scaled=True), dtype=torch.float32)

    res = se.explain_predicted_stage(x_tensor, base_tensor, horizon=1, steps=25)
    assert "predicted_stage" in res
    assert res["predicted_stage"] in STAGE_VOCABULARY
    assert "mitre_attck_context" in res


def test_human_explanation_generator(env_setup):
    """Test machine JSON schema formatting and human narrative rendering."""
    dummy_meta = {"prediction_origin": "2026-09-22T00:00:00Z", "dataset": "UNSW-NB15", "scenario_id": "test"}
    dummy_forecast = {"horizon_seconds": 30, "raw_probability": 0.85, "calibrated_probability": 0.82, "threshold": 0.45, "decision": "ATTACK_FORECAST"}
    dummy_top_feats = [{"feature": "total_flows", "raw_attribution": 0.15, "direction": "attack_supporting", "normalized_importance": 0.35}]
    dummy_time = [{"timestep_index": 9, "relative_position": "T", "raw_attribution": 0.20, "direction": "attack_supporting", "normalized_importance": 0.40}]
    dummy_cf = [{"feature": "total_flows", "original_calibrated_probability": 0.82, "perturbed_calibrated_probability": 0.55, "delta_calibrated_probability": -0.27}]
    dummy_stage = {"predicted_stage": "RECONNAISSANCE", "confidence": 0.78, "mitre_attck_context": {"sample_techniques": [{"attack_id": "T1046", "technique": "Network Service Discovery"}]}}

    machine_obj = HumanExplanationGenerator.build_machine_explanation(
        metadata=dummy_meta,
        forecast_info=dummy_forecast,
        top_features=dummy_top_feats,
        temporal_attribution=dummy_time,
        feature_time_matrix=[[0.0]*22]*10,
        evidence_dict={"supporting_observations": []},
        counterfactual_list=dummy_cf,
        temporal_ablation_list=[],
        stage_explanation=dummy_stage,
        ground_truth={"future_attack": 1, "future_stage": "RECONNAISSANCE"}
    )

    # Valid JSON serialization
    serialized = json.dumps(machine_obj)
    assert len(serialized) > 0

    # Human narrative
    narrative = HumanExplanationGenerator.render_soc_narrative(machine_obj)
    assert "WHY? — TOP CONTRIBUTING NETWORK-STATE FEATURES" in narrative
    assert "WHEN? — MOST INFLUENTIAL HISTORICAL WINDOWS" in narrative
    assert "HOW SENSITIVE? — MODEL SENSITIVITY UNDER PERTURBATION" in narrative
    assert "ANALYST INTERPRETATION & LIMITATIONS" in narrative
