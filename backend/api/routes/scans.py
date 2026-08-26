"""Scan management endpoints."""

from __future__ import annotations

import uuid
from datetime import UTC

from fastapi import APIRouter, HTTPException

from backend.api.deps import SessionDep, get_project_or_404, get_scan_or_404
from backend.models.entities import Scan, ScanStatus, ScanTask
from backend.schemas.api import ScanCreate, ScanOut, ScanTaskOut
from engine.profiles import PROFILES

router = APIRouter(tags=["scans"])


@router.post("/projects/{project_id}/scans", response_model=ScanOut, status_code=202)
def create_scan(project_id: uuid.UUID, body: ScanCreate, session: SessionDep) -> Scan:
    get_project_or_404(session, project_id)
    if not session.query(Scan).filter(Scan.project_id == project_id).count() == 0:
        running = session.query(Scan).filter(
            Scan.project_id == project_id,
            Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING])).first()
        if running:
            raise HTTPException(status_code=409,
                                detail=f"scan {running.id} already {running.status.value} "
                                       f"for this project")
    if body.profile != "custom" and body.profile not in PROFILES:
        raise HTTPException(status_code=422, detail="unknown profile")
    scan = Scan(project_id=project_id, profile=body.profile,
                config={"user": body.config}, status=ScanStatus.QUEUED)
    session.add(scan)
    session.flush()
    return scan


@router.get("/projects/{project_id}/scans", response_model=list[ScanOut])
def list_project_scans(project_id: uuid.UUID, session: SessionDep) -> list[Scan]:
    get_project_or_404(session, project_id)
    return list(
        session.query(Scan).filter(Scan.project_id == project_id)
        .order_by(Scan.started_at.desc().nullslast(), Scan.id).all()
    )


@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: uuid.UUID, session: SessionDep) -> Scan:
    return get_scan_or_404(session, scan_id)


@router.get("/scans/{scan_id}/tasks", response_model=list[ScanTaskOut])
def get_scan_tasks(scan_id: uuid.UUID, session: SessionDep) -> list[ScanTask]:
    get_scan_or_404(session, scan_id)
    return list(session.query(ScanTask).filter(ScanTask.scan_id == scan_id).all())


@router.post("/scans/{scan_id}/stop", response_model=ScanOut)
def stop_scan(scan_id: uuid.UUID, session: SessionDep) -> Scan:
    scan = get_scan_or_404(session, scan_id)
    if scan.status not in (ScanStatus.QUEUED, ScanStatus.RUNNING):
        raise HTTPException(status_code=409, detail=f"scan is {scan.status.value}")
    scan.stop_requested = True
    if scan.status == ScanStatus.QUEUED:
        scan.status = ScanStatus.STOPPED
        from datetime import datetime

        scan.finished_at = datetime.now(UTC)
    return scan
