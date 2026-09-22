"""
Unit tests for the NEXUS-Forecast Dashboard Backend API and Web Application.
"""

import pytest
from fastapi.testclient import TestClient
from src.dashboard.app import app


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_serve_index(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "NEXUS-FORECAST" in response.text
    assert "NETWORK THREATS" in response.text
    assert "OFFLINE SYSTEM" in response.text


def test_api_status(client):
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "OFFLINE_OPERATIONAL"
    assert data["network_access"] is False
    assert data["operational_threshold"] == 0.45
    assert data["artifacts_verified"] == 9


def test_api_dashboard_overview(client):
    response = client.get("/api/dashboard/overview?dataset=CIC-IDS2017&scenario=Scenario+01")
    assert response.status_code == 200
    data = response.json()
    assert "primary_forecast" in data
    assert "timeline" in data
    assert "evidence" in data
    assert "stage_progression" in data
    assert "top_features" in data
    assert "recent_forecasts" in data
    assert len(data["timeline"]) == 7
    assert len(data["stage_progression"]["stages"]) == 8


def test_api_inference_run(client):
    payload = {
        "input_type": "demo",
        "dataset": "CIC-IDS2017",
        "scenario": "Scenario 01",
        "horizons": [1, 3, 6],
        "explain": True,
        "enrich_attack": True,
        "enrich_capec": True,
    }
    response = client.post("/api/inference/run", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "forecast_id" in data
    assert "horizons" in data
    assert "h1" in data["horizons"]
    assert "h3" in data["horizons"]
    assert "h6" in data["horizons"]


def test_api_forecasts(client):
    response = client.get("/api/forecasts")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0


def test_api_explanations(client):
    response = client.get("/api/explanations")
    assert response.status_code == 200
    data = response.json()
    assert "feature_attribution" in data
    assert "temporal_attribution" in data
    assert "heatmap_matrix" in data
    assert "sensitivity" in data
    assert "error_analysis" in data
    assert len(data["temporal_attribution"]) == 10


def test_api_knowledge(client):
    response = client.get("/api/knowledge?stage=DISCOVERY")
    assert response.status_code == 200
    data = response.json()
    assert data["selected_stage"] == "DISCOVERY"
    assert "techniques" in data
    assert "capec_patterns" in data
    assert data["review_required_count"] == 19


def test_api_dataset_analysis(client):
    response = client.get("/api/dataset_analysis")
    assert response.status_code == 200
    data = response.json()
    assert "datasets" in data
    assert "CIC-IDS2017" in data["datasets"]
    assert "UNSW-NB15" in data["datasets"]
    assert "CTU-13" in data["datasets"]
    assert "+30s" in data["horizon_metrics"]


def test_api_reports_list(client):
    response = client.get("/api/reports")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 10
    assert any(r["phase"] == "Phase 19" for r in data)


def test_api_reports_view_and_download(client):
    # View
    res_view = client.get("/api/reports/view?path=reports/phase19/OFFLINE_PIPELINE_REPORT.md")
    assert res_view.status_code == 200
    view_data = res_view.json()
    assert "content" in view_data
    assert "NEXUS-Forecast" in view_data["content"]

    # Download
    res_down = client.get("/api/reports/download?path=reports/phase19/OFFLINE_PIPELINE_REPORT.md")
    assert res_down.status_code == 200
    assert len(res_down.content) > 100
