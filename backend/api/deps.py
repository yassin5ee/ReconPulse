"""Shared FastAPI dependencies."""

from typing import Annotated

from fastapi import Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.database.session import get_session

SessionDep = Annotated[Session, Depends(get_session)]


def pagination(limit: Annotated[int, Query(ge=1, le=1000)] = 50,
               offset: Annotated[int, Query(ge=0)] = 0) -> tuple[int, int]:
    return limit, offset


PaginationDep = Annotated[tuple[int, int], Depends(pagination)]


def get_project_or_404(session: Session, project_id):
    from backend.models.entities import Project

    project = session.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="project not found")
    return project


def get_scan_or_404(session: Session, scan_id):
    from backend.models.entities import Scan

    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return scan
