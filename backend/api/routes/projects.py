"""Project, target and scope management endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException

from backend.api.deps import SessionDep, get_project_or_404
from backend.models.entities import Project, RuleType, ScopeRule, Target
from backend.schemas.api import (
    ProjectCreate,
    ProjectOut,
    ProjectUpdate,
    ScopeRuleIn,
    ScopeRuleOut,
    TargetIn,
    TargetOut,
)
from engine.normalization import normalize_hostname

router = APIRouter(prefix="/projects", tags=["projects"])


@router.post("", response_model=ProjectOut, status_code=201)
def create_project(body: ProjectCreate, session: SessionDep) -> Project:
    if session.query(Project).filter(Project.name == body.name).first():
        raise HTTPException(status_code=409, detail="project name already exists")
    project = Project(name=body.name, description=body.description)
    session.add(project)
    session.flush()
    return project


@router.get("", response_model=list[ProjectOut])
def list_projects(session: SessionDep) -> list[Project]:
    return list(session.query(Project).order_by(Project.created_at).all())


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(project_id: uuid.UUID, session: SessionDep) -> Project:
    return get_project_or_404(session, project_id)


@router.patch("/{project_id}", response_model=ProjectOut)
def update_project(project_id: uuid.UUID, body: ProjectUpdate, session: SessionDep) -> Project:
    project = get_project_or_404(session, project_id)
    if body.description is not None:
        project.description = body.description
    return project


@router.delete("/{project_id}", status_code=204)
def delete_project(project_id: uuid.UUID, session: SessionDep) -> None:
    project = get_project_or_404(session, project_id)
    session.delete(project)


# ------------------------------------------------------------------ targets


def _validate_target(value: str, target_type: str) -> str:
    normalized = normalize_hostname(value) or value.strip()
    if target_type in ("domain",):
        if not normalized or "." not in normalized:
            raise HTTPException(status_code=422, detail=f"invalid domain: {value}")
        return normalized
    from engine.scope import is_ip

    if target_type == "ip" and not is_ip(normalized):
        raise HTTPException(status_code=422, detail=f"invalid ip: {value}")
    if target_type == "cidr":
        import ipaddress

        try:
            ipaddress.ip_network(value.strip(), strict=False)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"invalid cidr: {value}") from exc
    return normalized


@router.post("/{project_id}/targets", response_model=list[TargetOut], status_code=201)
def add_targets(project_id: uuid.UUID, bodies: list[TargetIn], session: SessionDep) -> list[Target]:
    get_project_or_404(session, project_id)
    created: list[Target] = []
    for body in bodies:
        value = _validate_target(body.value, body.target_type)
        exists = session.query(Target).filter(
            Target.project_id == project_id, Target.value == value).first()
        if exists:
            continue
        target = Target(project_id=project_id, value=value, target_type=body.target_type)
        session.add(target)
        session.flush()
        created.append(target)
        # convenience: seed ALLOW rules so the target is immediately scannable
        # (exact + wildcard for domains so discovered subdomains stay in scope)
        patterns = {value}
        if body.target_type == "domain":
            patterns.add(f"*.{value}")
        for pat in patterns:
            if not session.query(ScopeRule).filter(
                    ScopeRule.project_id == project_id,
                    ScopeRule.pattern == pat,
                    ScopeRule.rule_type == RuleType.ALLOW).first():
                session.add(ScopeRule(project_id=project_id, pattern=pat,
                                      rule_type=RuleType.ALLOW,
                                      comment="auto: added with target"))
    return created


@router.get("/{project_id}/targets", response_model=list[TargetOut])
def list_targets(project_id: uuid.UUID, session: SessionDep) -> list[Target]:
    get_project_or_404(session, project_id)
    return list(session.query(Target).filter(Target.project_id == project_id).all())


# ------------------------------------------------------------------ scope


@router.post("/{project_id}/scope", response_model=list[ScopeRuleOut], status_code=201)
def set_scope_rules(project_id: uuid.UUID, bodies: list[ScopeRuleIn],
                    session: SessionDep) -> list[ScopeRule]:
    get_project_or_404(session, project_id)
    created = []
    for body in bodies:
        # lowercase/strip only; wildcards (*.example.com) and CIDRs stay verbatim
        rule = ScopeRule(project_id=project_id, pattern=body.pattern.strip().lower(),
                         rule_type=RuleType(body.rule_type), comment=body.comment)
        session.add(rule)
        created.append(rule)
    session.flush()
    return created


@router.get("/{project_id}/scope", response_model=list[ScopeRuleOut])
def list_scope_rules(project_id: uuid.UUID, session: SessionDep) -> list[ScopeRule]:
    get_project_or_404(session, project_id)
    return list(session.query(ScopeRule).filter(ScopeRule.project_id == project_id).all())


@router.delete("/{project_id}/scope/{rule_id}", status_code=204)
def delete_scope_rule(project_id: uuid.UUID, rule_id: uuid.UUID, session: SessionDep) -> None:
    get_project_or_404(session, project_id)
    rule = session.get(ScopeRule, rule_id)
    if rule is None or rule.project_id != project_id:
        raise HTTPException(status_code=404, detail="rule not found")
    session.delete(rule)
