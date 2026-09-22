"""
FastAPI Main Application for NEXUS-Forecast Offline Analyst Workstation.
Integrates all Phase 12-21 analytical capabilities into a unified air-gapped system.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from backend.app.config import settings
from backend.app.api import (
    health,
    datasets,
    scenarios,
    inference,
    forecasts,
    explanations,
    knowledge,
    reports
)

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="Offline Air-Gapped Network Attack Forecasting & Threat Intelligence System (SIH PS26153)"
)

# Local air-gapped CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(health.router, prefix="/api")
app.include_router(datasets.router, prefix="/api")
app.include_router(scenarios.router, prefix="/api")
app.include_router(inference.router, prefix="/api")
app.include_router(forecasts.router, prefix="/api")
app.include_router(explanations.router, prefix="/api")
app.include_router(knowledge.router, prefix="/api")
app.include_router(reports.router, prefix="/api")

# Mount Static UI Assets
if settings.static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(settings.static_dir)), name="static")

    @app.get("/", response_class=HTMLResponse)
    def serve_frontend_root():
        index_file = settings.static_dir / "index.html"
        if index_file.exists():
            return HTMLResponse(content=index_file.read_text(encoding="utf-8"))
        return HTMLResponse(content="<h1>NEXUS-Forecast UI not found</h1>", status_code=404)
