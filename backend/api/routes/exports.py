"""Report export endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Response

from backend.api.deps import SessionDep, get_project_or_404
from services.export_service import (
    export_csv,
    export_html,
    export_json,
    export_markdown,
)

router = APIRouter(prefix="/projects/{project_id}/report", tags=["report"])

EXPORTERS = {
    "json": ("application/json", "reconpulse-report.json", export_json),
    "csv": ("text/csv", "reconpulse-report.csv", export_csv),
    "markdown": ("text/markdown", "reconpulse-report.md", export_markdown),
    "md": ("text/markdown", "reconpulse-report.md", export_markdown),
    "html": ("text/html", "reconpulse-report.html", export_html),
}


@router.get("")
def export_report(project_id: uuid.UUID, session: SessionDep,
                  format: str = "json") -> Response:
    get_project_or_404(session, project_id)
    if format not in EXPORTERS:
        raise HTTPException(status_code=422,
                            detail=f"format must be one of: {', '.join(EXPORTERS)}")
    media_type, filename, exporter = EXPORTERS[format]
    content = exporter(session, project_id)
    return Response(content=content, media_type=media_type,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})
