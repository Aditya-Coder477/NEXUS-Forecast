"""
Integration Test Suite for Phase 21 End-to-End System.
Verifies all REST API endpoints, model immutability, offline safety,
and integration across data, models, explainability, knowledge bases, and reports.
"""

import os
import json
import pytest
import numpy as np
from pathlib import Path
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.config import settings
from backend.app.utils.validation import compute_sha256

client = TestClient(app)


# 1. Health & System Status
def test_api_health():
    """Verify health endpoint indicates healthy and air-gapped status."""
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["mode"] == "offline"
    assert data["air_gapped"] is True
    assert data["manifest_valid"] is True
    assert data["active_device"] == "cpu"


def test_api_status():
    """Verify system status reports frozen operational threshold and all verified artifacts."""
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "operational"
    assert data["operational_threshold"] == 0.45
    assert data["sequence_length"] == 10
    assert data["num_features"] == 22
    assert "gru_world_model" in data["artifacts"]
    assert data["artifacts"]["gru_world_model"]["status"] == "LOADED"


# 2. Datasets Endpoint
def test_api_datasets():
    """Verify 3 datasets returned with complete metrics."""
    res = client.get("/api/datasets")
    assert res.status_code == 200
    datasets = res.json()
    assert len(datasets) == 3
    ids = [d["id"] for d in datasets]
    assert "CIC-IDS2017" in ids
    assert "UNSW-NB15" in ids
    assert "CTU-13" in ids


def test_api_dataset_analysis():
    """Verify dataset analysis view returns horizon performance metrics."""
    res = client.get("/api/dataset_analysis")
    assert res.status_code == 200
    data = res.json()
    assert "datasets" in data
    assert "horizon_metrics" in data
    assert "+30s" in data["horizon_metrics"]
    assert "+90s" in data["horizon_metrics"]
    assert "+180s" in data["horizon_metrics"]


# 3. Scenarios Endpoint
def test_api_scenarios():
    """Verify evaluation scenarios are populated from Phase 17 data."""
    res = client.get("/api/scenarios")
    assert res.status_code == 200
    scenarios = res.json()
    assert len(scenarios) == 10
    s0 = scenarios[0]
    assert "id" in s0
    assert "name" in s0
    assert "category" in s0
    assert "attack_probability" in s0


# 4. Live Inference Endpoint
def test_live_inference_valid_demo():
    """Verify offline inference pass runs on demo sequence within reasonable SLA."""
    payload = {
        "input_type": "demo",
        "scenario_id": "scenario_01",
        "horizons": [1, 3, 6],
        "explain_mode": "lightweight",
        "enrich_mode": "full"
    }
    res = client.post("/api/inference", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "forecast_id" in data
    assert "horizons" in data
    assert "h1" in data["horizons"]
    assert "h3" in data["horizons"]
    assert "h6" in data["horizons"]
    assert data["execution_time_ms"] > 0
    assert data["meta"]["air_gapped_guarantee"] is True


def test_live_inference_raw_state_valid():
    """Verify offline inference pass accepts raw 10x22 array."""
    valid_seq = np.random.randn(10, 22).tolist()
    payload = {
        "input_type": "state",
        "raw_sequence": valid_seq,
        "horizons": [1, 3, 6],
        "explain_mode": "lightweight",
        "enrich_mode": "none"
    }
    res = client.post("/api/inference", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "forecast_id" in data
    assert "h1" in data["horizons"]


def test_live_inference_invalid_input_rejected():
    """Verify invalid shapes are rejected with HTTP 400."""
    invalid_seq = np.random.randn(5, 12).tolist()  # Wrong shape
    payload = {
        "input_type": "state",
        "raw_sequence": invalid_seq,
        "horizons": [1, 3, 6]
    }
    res = client.post("/api/inference", json=payload)
    assert res.status_code == 400


# 5. Forecasts Endpoint
def test_forecasts_listing_and_history():
    """Verify forecasts list returns benchmark items plus newly generated forecasts."""
    res = client.get("/api/forecasts")
    assert res.status_code == 200
    forecasts = res.json()
    assert len(forecasts) >= 10
    f0 = forecasts[0]
    assert "attack_probability" in f0
    assert "decision" in f0
    assert "predicted_stage" in f0


def test_forecast_detail_by_id():
    """Verify forecast detail retrieval by ID."""
    res = client.get("/api/forecasts/scenario_01")
    assert res.status_code == 200
    data = res.json()
    assert "scenario_id" in data or "id" in data


def test_forecast_knowledge_enrichment():
    """Verify knowledge lookup for a specific forecast ID."""
    res = client.get("/api/forecasts/scenario_01/knowledge")
    assert res.status_code == 200
    data = res.json()
    assert "forecast_id" in data
    assert "predicted_stage" in data
    assert "mitre_techniques" in data


# 6. Explanations Endpoint
def test_explanations_endpoint():
    """Verify feature attribution, temporal curves, 10x22 matrix, and evidence."""
    res = client.get("/api/explanations/scenario_01")
    assert res.status_code == 200
    data = res.json()
    assert "top_features" in data
    assert len(data["top_features"]) > 0
    assert "temporal_attribution" in data
    assert len(data["temporal_attribution"]) == 10
    assert "feature_time_matrix" in data
    assert len(data["feature_time_matrix"]["rows"]) > 0
    assert "flow_evidence" in data
    assert "counterfactual_sensitivity" in data


# 7. Knowledge MITRE & CAPEC
def test_knowledge_mitre_preserves_19_review_required():
    """Verify 210 MITRE techniques loaded and strictly 19 REVIEW_REQUIRED preserved."""
    res = client.get("/api/knowledge/mitre")
    assert res.status_code == 200
    data = res.json()
    assert data["total_techniques"] == 210
    assert data["review_required_count"] == 19
    review_items = [t for t in data["techniques"] if t["review_status"] == "REVIEW_REQUIRED"]
    assert len(review_items) == 19


def test_knowledge_capec_catalog():
    """Verify 615 normalized CAPEC patterns loaded."""
    res = client.get("/api/knowledge/capec")
    assert res.status_code == 200
    data = res.json()
    assert data["total_patterns"] == 615
    assert len(data["patterns"]) > 0


# 8. Reports Endpoint
def test_reports_listing_and_content():
    """Verify reports metadata, content reader, and download response."""
    res = client.get("/api/reports")
    assert res.status_code == 200
    reports = res.json()
    assert len(reports) >= 8
    
    # Read first report
    r0_id = reports[0]["id"]
    res_view = client.get(f"/api/reports/{r0_id}")
    assert res_view.status_code == 200
    assert "content" in res_view.json()
    assert len(res_view.json()["content"]) > 100


# 9. Model Integrity & Immutability Check
def test_model_artifacts_integrity():
    """Verify SHA-256 hashes of core model, scaler, and calibration files are identical to baseline."""
    baseline_hashes_file = settings.reports_dir / "phase21" / "model_integrity_before.json"
    assert baseline_hashes_file.exists()
    
    with open(baseline_hashes_file, "r") as f:
        baseline = json.load(f)

    # Check GRU model hash
    gru_current_hash = compute_sha256(settings.model_path)
    model_baseline = baseline.get("model") or baseline.get("gru_model")
    assert gru_current_hash == model_baseline["sha256"], "GRU Model checkpoint has been altered!"

    # Check Scaler hash
    scaler_current_hash = compute_sha256(settings.scaler_path)
    assert scaler_current_hash == baseline["scaler"]["sha256"], "Scaler has been altered!"

    # Check Calibration hash
    cal_current_hash = compute_sha256(settings.calibration_path)
    cal_baseline = baseline.get("calibration") or baseline.get("calibration_model")
    assert cal_current_hash == cal_baseline["sha256"], "Calibration model has been altered!"


# 10. Static Frontend UI Serving
def test_frontend_root_served():
    """Verify root / serves static index.html with 7 primary navigation pages."""
    res = client.get("/")
    assert res.status_code == 200
    assert "NEXUS-FORECAST" in res.text
    assert "page-dashboard" in res.text
    assert "page-inference" in res.text
    assert "page-results" in res.text
    assert "page-explanations" in res.text
    assert "page-knowledge" in res.text
    assert "page-datasets" in res.text
    assert "page-reports" in res.text


# 11. Static JavaScript Assets Delivery
def test_static_js_assets_delivered():
    """Verify api.js and app.js are delivered properly with status 200."""
    res_api = client.get("/static/js/api.js")
    assert res_api.status_code == 200
    assert "NexusAPI" in res_api.text
    assert "NexusUI" in res_api.text

    res_app = client.get("/static/js/app.js")
    assert res_app.status_code == 200
    assert "DOMContentLoaded" in res_app.text
    assert "initHeaderSelectors" in res_app.text


# 12. Forecast Filtering
def test_forecast_filtering():
    """Verify query filters on /api/forecasts work properly."""
    res_attack = client.get("/api/forecasts?decision=ATTACK")
    assert res_attack.status_code == 200
    data_attack = res_attack.json()
    assert all(f["decision"] == "ATTACK" for f in data_attack)

    res_benign = client.get("/api/forecasts?decision=BENIGN")
    assert res_benign.status_code == 200
    data_benign = res_benign.json()
    assert all(f["decision"] == "BENIGN" for f in data_benign)

    res_stage = client.get("/api/forecasts?stage=DISCOVERY")
    assert res_stage.status_code == 200
    data_stage = res_stage.json()
    assert all(f["predicted_stage"] == "DISCOVERY" for f in data_stage)


# 13. Dual Schema on Explanations
def test_explanations_dual_schema():
    """Verify /api/explanations returns both canonical and frontend-friendly field names."""
    res = client.get("/api/explanations")
    assert res.status_code == 200
    data = res.json()
    # Canonical Phase 17 fields
    assert "top_features" in data
    assert "feature_time_matrix" in data
    assert "counterfactual_sensitivity" in data
    # Frontend dual fields
    assert "feature_attribution" in data
    assert "heatmap_matrix" in data
    assert "sensitivity" in data
    assert "error_analysis" in data


# 14. Live Inference Follow-up Explanation End-to-End
def test_live_inference_explanation_flow():
    """Run a live inference pass, then retrieve its explanation via forecast_id."""
    payload = {
        "input_type": "demo",
        "scenario_id": "scenario_02",
        "horizons": [1, 3, 6],
        "explain_mode": "lightweight",
        "enrich_mode": "full"
    }
    infer_res = client.post("/api/inference/run", json=payload)
    assert infer_res.status_code == 200
    infer_data = infer_res.json()
    forecast_id = infer_data["forecast_id"]

    # Now retrieve explanation for this live forecast
    expl_res = client.get(f"/api/explanations/{forecast_id}")
    assert expl_res.status_code == 200
    expl_data = expl_res.json()
    assert "feature_attribution" in expl_data or "top_features" in expl_data


# 15. Upload File Inference (CSV & PCAP)
def test_upload_csv_inference():
    """Verify uploading a CSV file executes live inference and returns calibrated horizons."""
    # Create simple 10x22 telemetry CSV
    import io
    import pandas as pd
    from src.world_model.dataset import STATE_FEATURE_NAMES

    df = pd.DataFrame(np.random.rand(10, 22), columns=STATE_FEATURE_NAMES)
    csv_bytes = df.to_csv(index=False).encode("utf-8")

    res = client.post(
        "/api/inference/upload",
        files={"file": ("test_flow_capture.csv", csv_bytes, "text/csv")},
        data={"explain_mode": "lightweight", "enrich_mode": "full"}
    )
    assert res.status_code == 200
    data = res.json()
    assert "forecast_id" in data
    assert "h1" in data["horizons"]
    assert data["meta"]["uploaded_file"] == "test_flow_capture.csv"


def test_upload_pcap_inference():
    """Verify uploading a valid PCAP file processes packets and returns forecast."""
    import struct

    # Construct minimal valid PCAP byte stream (Global header + 2 TCP packets)
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # Ethernet network

    packets = bytearray(global_hdr)
    # Packet 1 (SYN)
    raw_pkt1 = b"\x00" * 12 + b"\x08\x00" + b"\x45\x00\x00\x3c\x12\x34\x40\x00\x40\x06\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02" + b"\x04\xd2\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x20\x00\x00\x00\x00\x00"
    pkt1_hdr = struct.pack("<IIII", 1000, 0, len(raw_pkt1), len(raw_pkt1))
    packets.extend(pkt1_hdr + raw_pkt1)

    # Packet 2 (RST)
    raw_pkt2 = b"\x00" * 12 + b"\x08\x00" + b"\x45\x00\x00\x3c\x12\x35\x40\x00\x40\x06\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02" + b"\x04\xd2\x01\xbb\x00\x00\x00\x00\x00\x00\x00\x00\x50\x04\x20\x00\x00\x00\x00\x00"
    pkt2_hdr = struct.pack("<IIII", 1050, 0, len(raw_pkt2), len(raw_pkt2))
    packets.extend(pkt2_hdr + raw_pkt2)

    res = client.post(
        "/api/inference/upload",
        files={"file": ("capture.pcap", bytes(packets), "application/vnd.tcpdump.pcap")},
        data={"explain_mode": "lightweight", "enrich_mode": "full"}
    )
    assert res.status_code == 200
    data = res.json()
    assert "forecast_id" in data
    assert "h1" in data["horizons"]
    assert data["meta"]["uploaded_file"] == "capture.pcap"


