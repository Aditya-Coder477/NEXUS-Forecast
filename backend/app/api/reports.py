"""
Reports API router.
"""

from typing import List
from fastapi import APIRouter
from fastapi.responses import FileResponse
from backend.app.schemas.report import ReportMetadata, ReportDetailResponse
from backend.app.services.report_service import ReportService

router = APIRouter(tags=["Reports"])


@router.get("/reports", response_model=List[ReportMetadata])
def list_reports():
    """Retrieve metadata of all available engineering and audit reports."""
    return ReportService.list_reports()


@router.get("/reports/view")
def view_report_by_path(path: str = None):
    """View report content by path or query."""
    reports = ReportService.list_reports()
    if path:
        # Match by filename or path substring
        for r in reports:
            if path in r["filename"] or r["id"] in path:
                return ReportService.get_report_content(r["id"])
    if reports:
        return ReportService.get_report_content(reports[0]["id"])
    return {"content": "No reports available"}


@router.get("/reports/download")
def download_report_by_path(path: str = None):
    """Download report file by path or query."""
    reports = ReportService.list_reports()
    target_id = reports[0]["id"] if reports else None
    if path:
        for r in reports:
            if path in r["filename"] or r["id"] in path:
                target_id = r["id"]
                break
    file_path = ReportService.get_report_file_path(target_id)
    return FileResponse(
        path=str(file_path),
        filename=file_path.name,
        media_type="text/markdown"
    )


@router.get("/reports/{report_id}", response_model=ReportDetailResponse)
def get_report(report_id: str):
    """Retrieve rendered content of a specific report."""
    return ReportService.get_report_content(report_id)


@router.get("/reports/{report_id}/download")
def download_report(report_id: str):
    """Download the raw Markdown report file."""
    path = ReportService.get_report_file_path(report_id)
    return FileResponse(
        path=str(path),
        filename=path.name,
        media_type="text/markdown"
    )
