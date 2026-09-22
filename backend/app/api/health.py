"""
Health and Status API endpoints.
"""

from fastapi import APIRouter
from backend.app.config import settings
from backend.app.schemas.common import HealthResponse, PipelineStatusResponse
from backend.app.utils.validation import compute_sha256

router = APIRouter(tags=["Health & Status"])


@router.api_route("/health", methods=["GET", "HEAD"], response_model=HealthResponse)
def get_health():
    """Check API health and offline status."""
    return HealthResponse(
        status="healthy",
        version=settings.version,
        mode="offline",
        air_gapped=True,
        manifest_valid=settings.manifest_path.exists(),
        active_device=settings.device
    )


@router.get("/status", response_model=PipelineStatusResponse)
def get_status():
    """Return pipeline details, model hashes, and operational thresholds."""
    artifacts_info = {}
    targets = [
        ("gru_world_model", settings.model_path),
        ("scaler", settings.scaler_path),
        ("calibration_model", settings.calibration_path),
        ("baseline_statistics", settings.baseline_path),
        ("mitre_mapping", settings.mitre_stage_mapping_path),
        ("capec_catalog", settings.capec_path),
        ("manifest", settings.manifest_path),
    ]
    for name, p in targets:
        if p.exists():
            artifacts_info[name] = {
                "path": str(p),
                "sha256": compute_sha256(p),
                "size_bytes": p.stat().st_size,
                "status": "LOADED"
            }
        else:
            artifacts_info[name] = {"path": str(p), "status": "MISSING"}

    return PipelineStatusResponse(
        status="operational",
        version=settings.version,
        operational_threshold=settings.operational_threshold,
        sequence_length=10,
        num_features=22,
        horizons=[1, 3, 6],
        artifacts=artifacts_info
    )
