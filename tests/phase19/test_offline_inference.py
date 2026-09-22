"""
Comprehensive Unit and Integration Test Suite for NEXUS-Forecast Phase 19.
Tests offline inference, cryptographic manifest verification, input validation,
determinism, air-gapped isolation, latency SLAs, and output formatting.
"""

import os
import sys
import json
import socket
import pytest
import numpy as np
import pandas as pd
import subprocess

from src.inference.config import InferenceConfig
from src.inference.loader import ModelLoader, IntegrityError
from src.inference.validator import InputValidator, ValidationError
from src.inference.pipeline import OfflineInferencePipeline
from src.inference.output import OutputFormatter


@pytest.fixture(scope="module")
def config():
    return InferenceConfig()


@pytest.fixture(scope="module")
def pipeline(config):
    return OfflineInferencePipeline(config)


# 1. Manifest & Cryptographic Tests
def test_manifest_verification_success(config):
    loader = ModelLoader(config)
    results = loader.verify_manifest()
    assert len(results) == 9
    assert all(results.values())


def test_manifest_tamper_detection(tmp_path):
    # Create fake manifest with incorrect hash
    fake_manifest = {
        "version": "1.0.0",
        "artifacts": {
            "models/world_model/gru/best_model.pt": {
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                "size_bytes": 100,
            }
        }
    }
    m_path = tmp_path / "fake_manifest.json"
    with open(m_path, "w") as f:
        json.dump(fake_manifest, f)

    bad_config = InferenceConfig(manifest_path=str(m_path))
    loader = ModelLoader(bad_config)
    with pytest.raises(IntegrityError) as exc_info:
        loader.verify_manifest()
    assert "Cryptographic hash mismatch" in str(exc_info.value)


def test_missing_artifact_detection(tmp_path):
    fake_manifest = {
        "version": "1.0.0",
        "artifacts": {
            "non_existent_model_file.pt": {
                "sha256": "abcdef123456",
                "size_bytes": 10,
            }
        }
    }
    m_path = tmp_path / "missing_manifest.json"
    with open(m_path, "w") as f:
        json.dump(fake_manifest, f)

    bad_config = InferenceConfig(manifest_path=str(m_path))
    loader = ModelLoader(bad_config)
    with pytest.raises(IntegrityError) as exc_info:
        loader.verify_manifest()
    assert "missing" in str(exc_info.value)


# 2. Configuration & Input Validation Tests
def test_config_validation():
    with pytest.raises(ValueError):
        InferenceConfig(operational_threshold=1.5).validate()
    with pytest.raises(ValueError):
        InferenceConfig(sequence_length=12).validate()
    with pytest.raises(ValueError):
        InferenceConfig(num_features=20).validate()
    with pytest.raises(ValueError):
        InferenceConfig(explain_mode="invalid_mode").validate()


def test_input_validator_valid_2d():
    arr_2d = np.zeros((10, 22), dtype=np.float32)
    validated = InputValidator.validate_sequence_array(arr_2d)
    assert validated.shape == (1, 10, 22)


def test_input_validator_valid_3d():
    arr_3d = np.zeros((4, 10, 22), dtype=np.float32)
    validated = InputValidator.validate_sequence_array(arr_3d)
    assert validated.shape == (4, 10, 22)


def test_input_validator_invalid_shape():
    with pytest.raises(ValidationError):
        InputValidator.validate_sequence_array(np.zeros((9, 22)))
    with pytest.raises(ValidationError):
        InputValidator.validate_sequence_array(np.zeros((10, 21)))


def test_input_validator_nan_rejection():
    arr = np.zeros((1, 10, 22), dtype=np.float32)
    arr[0, 2, 5] = np.nan
    with pytest.raises(ValidationError) as exc:
        InputValidator.validate_sequence_array(arr)
    assert "non-finite" in str(exc.value)


def test_input_validator_inf_rejection():
    arr = np.zeros((1, 10, 22), dtype=np.float32)
    arr[0, 2, 5] = np.inf
    with pytest.raises(ValidationError) as exc:
        InputValidator.validate_sequence_array(arr)
    assert "non-finite" in str(exc.value)


def test_extract_from_dataframe():
    demo_path = "data/demo/example_sequence.parquet"
    if os.path.exists(demo_path):
        df = pd.read_parquet(demo_path)
        arr = InputValidator.extract_sequences_from_dataframe(df)
        assert arr.ndim == 3
        assert arr.shape[1] == 10
        assert arr.shape[2] == 22


# 3. Pipeline Execution Tests
def test_pipeline_predict_single_sequence_basic(pipeline):
    dummy_seq = np.zeros((10, 22), dtype=np.float32)
    res = pipeline.predict_single_sequence(dummy_seq, explain_mode="none", enrich_mode="none")
    assert "forecast_id" in res
    assert "horizons" in res
    assert "h1" in res["horizons"]
    assert "h3" in res["horizons"]
    assert "h6" in res["horizons"]
    assert "summary" in res
    assert "threat_level" in res["summary"]


def test_pipeline_explain_modes(pipeline):
    dummy_seq = np.ones((10, 22), dtype=np.float32)

    # 1. none
    res_none = pipeline.predict_single_sequence(dummy_seq, explain_mode="none")
    assert "explanation" not in res_none["horizons"]["h1"]

    # 2. lightweight
    res_light = pipeline.predict_single_sequence(dummy_seq, explain_mode="lightweight")
    assert "explanation" in res_light["horizons"]["h1"]
    assert res_light["horizons"]["h1"]["explanation"]["mode"] == "lightweight"
    assert len(res_light["horizons"]["h1"]["explanation"]["top_contributing_features"]) == 5

    # 3. full
    res_full = pipeline.predict_single_sequence(dummy_seq, explain_mode="full")
    assert "explanation" in res_full["horizons"]["h1"]
    assert res_full["horizons"]["h1"]["explanation"]["mode"] == "full_integrated_gradients"


def test_pipeline_enrich_modes(pipeline):
    # Dummy sequence that simulates elevated network traffic
    active_seq = np.ones((10, 22), dtype=np.float32) * 50.0

    # 1. none
    res_none = pipeline.predict_single_sequence(active_seq, enrich_mode="none")
    assert "enrichment" not in res_none["horizons"]["h1"]

    # 2. attack
    res_att = pipeline.predict_single_sequence(active_seq, enrich_mode="attack")
    if res_att["horizons"]["h1"]["predicted_attack"]:
        assert "attack_techniques" in res_att["horizons"]["h1"]["enrichment"]
        assert "capec_patterns" not in res_att["horizons"]["h1"]["enrichment"]

    # 3. full
    res_full = pipeline.predict_single_sequence(active_seq, enrich_mode="full")
    if res_full["horizons"]["h1"]["predicted_attack"]:
        assert "attack_techniques" in res_full["horizons"]["h1"]["enrichment"]
        assert "capec_patterns" in res_full["horizons"]["h1"]["enrichment"]


def test_pipeline_determinism(pipeline):
    seq = np.random.RandomState(42).randn(10, 22).astype(np.float32)
    run1 = pipeline.predict_single_sequence(seq, explain_mode="lightweight", enrich_mode="full", forecast_id="DET-TEST")
    run2 = pipeline.predict_single_sequence(seq, explain_mode="lightweight", enrich_mode="full", forecast_id="DET-TEST")

    # Check probabilities are numerically identical
    for h in [1, 3, 6]:
        h_key = f"h{h}"
        assert run1["horizons"][h_key]["calibrated_attack_prob"] == run2["horizons"][h_key]["calibrated_attack_prob"]
        assert run1["horizons"][h_key]["predicted_attack"] == run2["horizons"][h_key]["predicted_attack"]
        assert run1["horizons"][h_key]["predicted_stage"] == run2["horizons"][h_key]["predicted_stage"]


def test_pipeline_threshold_application(pipeline):
    # Verify binary decision matches threshold rule
    dummy_seq = np.zeros((10, 22), dtype=np.float32)
    res = pipeline.predict_single_sequence(dummy_seq)
    for h_key, h_data in res["horizons"].items():
        prob = h_data["calibrated_attack_prob"]
        decision = h_data["predicted_attack"]
        expected_decision = (prob >= pipeline.config.operational_threshold)
        assert decision == expected_decision


def test_offline_network_block(monkeypatch, pipeline):
    def blocked_socket(*args, **kwargs):
        raise RuntimeError("Blocked network socket!")

    monkeypatch.setattr(socket, "socket", blocked_socket)

    dummy_seq = np.zeros((10, 22), dtype=np.float32)
    # Execution must succeed without touching network
    res = pipeline.predict_single_sequence(dummy_seq, explain_mode="lightweight", enrich_mode="full")
    assert res is not None
    assert "forecast_id" in res


def test_pipeline_latency_benchmark(pipeline):
    seq = np.zeros((10, 22), dtype=np.float32)
    # Warmup
    pipeline.predict_single_sequence(seq, explain_mode="lightweight", enrich_mode="none")

    import time
    times = []
    for _ in range(10):
        t0 = time.perf_counter()
        pipeline.predict_single_sequence(seq, explain_mode="lightweight", enrich_mode="none")
        times.append((time.perf_counter() - t0) * 1000.0)

    avg_ms = float(np.mean(times))
    assert avg_ms < 50.0, f"Average latency {avg_ms:.2f}ms exceeds SLA limit of 50ms"


def test_output_formatter_json_and_markdown(pipeline):
    dummy_seq = np.zeros((10, 22), dtype=np.float32)
    res = pipeline.predict_single_sequence(dummy_seq)

    json_str = OutputFormatter.to_json([res])
    assert "forecast_id" in json_str

    md_str = OutputFormatter.to_soc_markdown(res)
    assert "# NEXUS-Forecast Threat Intelligence Alert" in md_str
    assert "Horizon Breakdown" in md_str


def test_cli_execution():
    cmd = [
        sys.executable,
        "-m",
        "src.inference.run",
        "--input",
        "data/demo/example_sequence.parquet",
        "--input-type",
        "sequence",
        "--explain",
        "lightweight",
        "--enrich",
        "full",
        "--output",
        "outputs/test_cli_forecast.json",
        "--format",
        "json",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, f"CLI failed with error: {proc.stderr}"
    assert os.path.exists("outputs/test_cli_forecast.json")
    with open("outputs/test_cli_forecast.json") as f:
        data = json.load(f)
    assert len(data) == 5
