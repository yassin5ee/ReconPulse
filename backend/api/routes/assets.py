"""Asset endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import or_

from backend.api.deps import PaginationDep, SessionDep, get_project_or_404
from backend.models.entities import Asset, AssetType, ScopeStatus
from backend.schemas.api import AssetDetail, AssetOut

router = APIRouter(prefix="/projects/{project_id}", tags=["assets"])

TYPE_VALUES = [t.value for t in AssetType]


@router.get("/assets", response_model=list[AssetOut])
def list_assets(project_id: uuid.UUID, session: SessionDep, page: PaginationDep,
                asset_type: str | None = Query(None),
                scope_status: str | None = Query(None),
                search: str | None = Query(None),
                min_score: int = Query(0, ge=0, le=100)) -> list[Asset]:
    get_project_or_404(session, project_id)
    limit, offset = page
    q = session.query(Asset).filter(Asset.project_id == project_id)
    if asset_type:
        if asset_type not in TYPE_VALUES:
            raise HTTPException(status_code=422, detail="invalid asset_type")
        q = q.filter(Asset.asset_type == AssetType(asset_type))
    if scope_status:
        q = q.filter(Asset.scope_status == ScopeStatus(scope_status))
    if search:
        q = q.filter(Asset.value.contains(search))
    q = q.filter(Asset.priority_score >= min_score)
    return list(q.order_by(Asset.priority_score.desc(), Asset.value)
                .offset(offset).limit(limit).all())


@router.get("/assets/{asset_id}", response_model=AssetDetail)
def get_asset(project_id: uuid.UUID, asset_id: uuid.UUID, session: SessionDep) -> Asset:
    get_project_or_404(session, project_id)
    asset = session.get(Asset, asset_id)
    if asset is None or asset.project_id != project_id:
        raise HTTPException(status_code=404, detail="asset not found")
    # touch relationships so the detail serializer can include them lazily
    _ = (asset.services, asset.dns_records, asset.technologies, asset.findings)
    return asset


@router.get("/assets/search/{value}", response_model=list[AssetOut])
def search_exact(value: str, session: SessionDep) -> list[Asset]:
    return list(session.query(Asset).filter(or_(Asset.value == value)).limit(50).all())
