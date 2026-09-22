"""
Report Service for listing, reading, and securely downloading technical reports.
"""

import os
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from fastapi import HTTPException

from backend.app.config import settings
from backend.app.utils.validation import safe_path_join

# Authoritative registry of Phase 12-21 reports
REPORT_REGISTRY = [
    {
        "id": "phase13_baseline",
        "phase": "Phase 13",
        "title": "Logistic Regression Baseline Report",
        "category": "Modeling",
        "relative_path": "baseline/LOGISTIC_REGRESSION_BASELINE_REPORT.md",
        "summary": "Non-temporal linear reference model results establishing baseline F1 and ROC-AUC scores."
    },
    {
        "id": "phase14_lstm",
        "phase": "Phase 14",
        "title": "LSTM World Model Architecture & Evaluation",
        "category": "Deep Learning",
        "relative_path": "world_model/lstm/LSTM_WORLD_MODEL_REPORT.md",
        "summary": "First temporal recurrent world model benchmark across multi-horizon forecast tasks."
    },
    {
        "id": "phase15_gru",
        "phase": "Phase 15",
        "title": "GRU Temporal World Model Evaluation",
        "category": "Deep Learning",
        "relative_path": "world_model/gru/GRU_WORLD_MODEL_REPORT.md",
        "summary": "Evaluation of the GRU World Model achieving superior attack F1 and stage forecasting."
    },
    {
        "id": "phase15_comparison",
        "phase": "Phase 15",
        "title": "LSTM vs GRU Recurrent Comparison",
        "category": "Deep Learning",
        "relative_path": "world_model/lstm_vs_gru/LSTM_VS_GRU_COMPARISON.md",
        "summary": "Controlled comparative study establishing GRU as the optimal architecture candidate for PS26153."
    },
    {
        "id": "phase16_rollout",
        "phase": "Phase 16",
        "title": "Autoregressive Rollout & Platt Calibration",
        "category": "Inference Engineering",
        "relative_path": "phase16/PHASE16_FINAL_REPORT.md",
        "summary": "Empirical calibration, ROC/PR threshold analysis fixing theta*=0.45, and multi-step trajectory stability."
    },
    {
        "id": "phase17_explainability",
        "phase": "Phase 17",
        "title": "Explainability & Evidence Attribution Audit",
        "category": "Trust & Safety",
        "relative_path": "phase17/PHASE17_EXPLAINABILITY_REPORT.md",
        "summary": "Integrated Gradients (50 steps) with train-only baseline, 10x22 attribution matrix, and flow telemetry evidence."
    },
    {
        "id": "phase17_traceability",
        "phase": "Phase 17",
        "title": "Evidence Traceability Report",
        "category": "Trust & Safety",
        "relative_path": "phase17/EVIDENCE_TRACEABILITY_REPORT.md",
        "summary": "Mapping from 22 canonical temporal state features to raw observable network flow fields."
    },
    {
        "id": "phase18_enrichment",
        "phase": "Phase 18",
        "title": "MITRE ATT&CK & CAPEC Knowledge Mapping",
        "category": "Threat Intelligence",
        "relative_path": "phase18/PHASE18_ENRICHMENT_REPORT.md",
        "summary": "210 enterprise techniques mapped to 8 stages, with 19 REVIEW_REQUIRED techniques rigorously audited."
    },
    {
        "id": "phase19_offline",
        "phase": "Phase 19",
        "title": "Air-Gapped Offline Inference Architecture",
        "category": "System Architecture",
        "relative_path": "phase19/OFFLINE_PIPELINE_REPORT.md",
        "summary": "Production CLI, manifest cryptographic checks, sub-35ms SLA verification, and zero-cloud compliance."
    },
    {
        "id": "phase21_audit",
        "phase": "Phase 21",
        "title": "Phase 21 Pre-Integration Audit Report",
        "category": "Integration",
        "relative_path": "phase21/PHASE21_PRE_INTEGRATION_AUDIT.md",
        "summary": "Inventory of frontend views, backend modules, frozen hashes, and API integration contract."
    }
]


class ReportService:
    @staticmethod
    def list_reports() -> List[Dict[str, Any]]:
        """List all available reports with real file metadata."""
        items = []
        for r in REPORT_REGISTRY:
            p = settings.reports_dir / r["relative_path"]
            exists = p.exists()
            size = p.stat().st_size if exists else 0
            mtime = datetime.datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M") if exists else "N/A"
            items.append({
                "id": r["id"],
                "phase": r["phase"],
                "title": r["title"],
                "category": r["category"],
                "filename": p.name,
                "size_bytes": size,
                "last_modified": mtime,
                "summary": r["summary"],
                "available": exists
            })
        return items

    @staticmethod
    def get_report_content(report_id: str) -> Dict[str, Any]:
        """Fetch content of a single report with strict path safety."""
        found = next((r for r in REPORT_REGISTRY if r["id"] == report_id), None)
        if not found:
            raise HTTPException(status_code=404, detail=f"Report {report_id} not found in registry")

        file_path = safe_path_join(settings.reports_dir, found["relative_path"])
        if not file_path.exists():
            raise HTTPException(status_code=404, detail=f"Report file {file_path.name} not found on disk")

        content = file_path.read_text(encoding="utf-8")
        return {
            "id": found["id"],
            "title": found["title"],
            "filename": file_path.name,
            "content": content,
            "size_bytes": file_path.stat().st_size,
            "last_modified": datetime.datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
        }

    @staticmethod
    def get_report_file_path(report_id: str) -> Path:
        """Return the secure Path object for file download."""
        found = next((r for r in REPORT_REGISTRY if r["id"] == report_id), None)
        if not found:
            raise HTTPException(status_code=404, detail=f"Report {report_id} not found in registry")
        
        file_path = safe_path_join(settings.reports_dir, found["relative_path"])
        if not file_path.exists():
            raise HTTPException(status_code=404, detail=f"Report file not found")
        return file_path
