"""
Inference API router.
"""

from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from backend.app.schemas.inference import InferenceRequest, InferenceResponse
from backend.app.services.inference_service import InferenceService
from backend.app.services.forecast_service import ForecastService
from backend.app.services.upload_service import UploadService

router = APIRouter(tags=["Inference"])


@router.post("/inference", response_model=InferenceResponse)
@router.post("/inference/run", response_model=InferenceResponse)
def execute_inference(req: InferenceRequest):
    """
    Run offline inference using the frozen GRU World Model.
    """
    try:
        result = InferenceService.run_inference(
            input_type=req.input_type,
            scenario_id=req.scenario_id,
            raw_sequence=req.raw_sequence,
            horizons=req.horizons,
            explain_mode=req.explain_mode,
            enrich_mode=req.enrich_mode
        )
        # Store in forecast history
        sc_name = req.scenario_id or "Custom Inference"
        ForecastService.record_forecast(result, scenario_name=sc_name)
        return result
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference pipeline execution error: {str(e)}")


@router.post("/inference/upload", response_model=InferenceResponse)
async def upload_and_infer(
    file: UploadFile = File(...),
    explain_mode: str = Form(default="lightweight"),
    enrich_mode: str = Form(default="full")
):
    """
    Accept an uploaded PCAP, CSV, or Parquet file, aggregate into 10 temporal windows,
    and run offline inference with the frozen GRU World Model.
    """
    try:
        content = await file.read()
        if not content:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")
        
        result = UploadService.process_and_forecast(
            file_bytes=content,
            filename=file.filename or "uploaded_network_telemetry.pcap",
            explain_mode=explain_mode,
            enrich_mode=enrich_mode
        )
        
        # Store in forecast history
        ForecastService.record_forecast(result, scenario_name=f"Upload: {file.filename}")
        return result
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File inference error: {str(e)}")
