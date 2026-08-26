"""Project statistics endpoint."""

from __future__ import annotations

import uuid

from fastapi import APIRouter

from backend.api.deps import SessionDep, get_project_or_404
from backend.models.entities import Asset, AssetType, Scan, Service, Technology
from backend.schemas.api import Statistics
from engine.scoring import high_priority_threshold

router = APIRouter(prefix="/projects/{project_id}", tags=["statistics"])


@router.get("/statistics", response_model=Statistics)
def statistics(project_id: uuid.UUID, session: SessionDep) -> Statistics:
    get_project_or_404(session, project_id)
    assets = session.query(Asset).filter(Asset.project_id == project_id).all()
    scans = (session.query(Scan).filter(Scan.project_id == project_id)
             .order_by(Scan.started_at.desc().nullslast()).all())
    last_scan = scans[0] if scans else None
    open_ports = sum(
        session.query(Service).join(Asset).filter(Asset.project_id == project_id).count()
        for _ in [0]
    )
    technologies = (
        session.query(Technology).join(Asset).filter(Asset.project_id == project_id).count()
    )
    from backend.models.entities import Finding

    finding_count = session.query(Finding).filter(Finding.project_id == project_id).count()
    return Statistics(
        assets=len(assets),
        domains=sum(1 for a in assets if a.asset_type == AssetType.DOMAIN),
        subdomains=sum(1 for a in assets if a.asset_type == AssetType.SUBDOMAIN),
        ips=sum(1 for a in assets if a.asset_type == AssetType.IP),
        urls=sum(1 for a in assets if a.asset_type == AssetType.URL),
        open_ports=open_ports,
        technologies=technologies,
        findings=finding_count,
        high_priority_assets=sum(
            1 for a in assets if a.priority_score >= high_priority_threshold()),
        scans_total=len(scans),
        last_scan_status=last_scan.status.value if last_scan else None,
    )
