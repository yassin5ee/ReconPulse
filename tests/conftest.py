"""Shared fixtures: in-memory SQLite database + FastAPI TestClient."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.api.app import create_app
from backend.api.deps import get_session
from backend.models.entities import Asset, AssetType, Base, DnsRecord, Project, Scan


@pytest.fixture()
def engine():
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def session_factory(engine):
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@pytest.fixture()
def client(session_factory):
    application = create_app()

    def override_get_session():
        db = session_factory()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    application.dependency_overrides[get_session] = override_get_session
    with TestClient(application) as c:
        yield c


@pytest.fixture()
def project_id(session_factory) -> uuid.UUID:
    """A project with example.com allowed and admin.example.com denied."""
    from backend.models.entities import RuleType, ScopeRule, Target

    with session_factory() as s:
        p = Project(name="acme", description="test project")
        s.add(p)
        s.flush()
        s.add(Target(project_id=p.id, value="example.com", target_type="domain"))
        s.add(ScopeRule(project_id=p.id, pattern="*.example.com",
                        rule_type=RuleType.ALLOW, comment="main domain"))
        s.add(ScopeRule(project_id=p.id, pattern="admin.example.com",
                        rule_type=RuleType.DENY, comment="excluded host"))
        s.commit()
        return p.id


def make_asset(session: sessionmaker, pid: uuid.UUID, value: str,
               asset_type: AssetType = AssetType.SUBDOMAIN, **kw) -> uuid.UUID:
    with session() as s:
        asset = Asset(project_id=pid, asset_type=asset_type, value=value, **kw)
        s.add(asset)
        s.commit()
        return asset.id


def make_dns_record(session: sessionmaker, asset_id: uuid.UUID, rtype: str,
                    value: str) -> None:
    with session() as s:
        s.add(DnsRecord(asset_id=asset_id, record_type=rtype, value=value,
                        source="test"))
        s.commit()


def make_scan(session: sessionmaker, pid: uuid.UUID,
              status: str = "queued") -> uuid.UUID:
    from backend.models.entities import ScanStatus

    with session() as s:
        scan = Scan(project_id=pid, profile="standard", status=ScanStatus(status))
        s.add(scan)
        s.commit()
        return scan.id
