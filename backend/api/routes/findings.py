"""Finding endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Query
from sqlalchemy.orm import joinedload

from backend.api.deps import PaginationDep, SessionDep, get_project_or_404
from backend.models.entities import Finding
from backend.schemas.api import FindingOut

router = APIRouter(prefix="/projects/{project_id}", tags=["findings"])


@router.get("/findings", response_model=list[FindingOut])
def list_findings(project_id: uuid.UUID, session: SessionDep, page: PaginationDep,
                  finding_type: str | None = Query(None),
                  min_priority: int = Query(0, ge=0, le=100)) -> list[Finding]:
    get_project_or_404(session, project_id)
    limit, offset = page
    q = (session.query(Finding)
         .options(joinedload(Finding.asset))
         .filter(Finding.project_id == project_id))
    if finding_type:
        q = q.filter(Finding.finding_type == finding_type)
    q = q.filter(Finding.priority >= min_priority)
    return list(q.order_by(Finding.priority.desc()).offset(offset).limit(limit).all())
