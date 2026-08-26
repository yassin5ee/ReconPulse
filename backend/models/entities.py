"""ReconPulse ORM models.

Normalized relational model. JSONB/JSON `metadata` is used only for genuinely
semi-structured data (HTTP headers, tool evidence); everything queryable is a column.
"""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_uuid() -> uuid.UUID:
    return uuid.uuid4()


class Base(DeclarativeBase):
    pass


class ScopeStatus(enum.StrEnum):
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    UNKNOWN = "UNKNOWN"


class AssetType(enum.StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    URL = "url"


class ScanStatus(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    STOPPED = "stopped"


class TaskStatus(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    SKIPPED = "skipped"
    FAILED = "failed"


class RuleType(enum.StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    targets: Mapped[list[Target]] = relationship(back_populates="project", cascade="all, delete-orphan")
    scope_rules: Mapped[list[ScopeRule]] = relationship(back_populates="project", cascade="all, delete-orphan")
    assets: Mapped[list[Asset]] = relationship(back_populates="project", cascade="all, delete-orphan")
    scans: Mapped[list[Scan]] = relationship(back_populates="project", cascade="all, delete-orphan")


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_uuid)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(500), nullable=False)
    target_type: Mapped[str] = mapped_column(String(30), default="domain")  # domain | ip | cidr | range
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    project: Mapped[Project] = relationship(back_populates="targets")


class ScopeRule(Base):
    __tablename__ = "scope_rules"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_uuid)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    # e.g. example.com, *.example.com, 10.0.0.0/24
    pattern: Mapped[str] = mapped_column(String(500), nullable=False)
    rule_type: Mapped[RuleType] = mapped_column(Enum(RuleType), nullable=False)
    comment: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    project: Mapped[Project] = relationship(back_populates="scope_rules")


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("project_id", "asset_type", "value", name="uq_asset"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_uuid)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    asset_type: Mapped[AssetType] = mapped_column(Enum(AssetType), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(1000), nullable=False, index=True)
    scope_status: Mapped[ScopeStatus] = mapped_column(Enum(ScopeStatus), default=ScopeStatus.UNKNOWN)
    priority_score: Mapped[int] = mapped_column(Integer, default=0)
    priority_reasons: Mapped[list] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    extra_data: Mapped[dict] = mapped_column("metadata", JSON, default=dict)

    project: Mapped[Project] = relationship(back_populates="assets")
    services: Mapped[list[Service]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    dns_records: Mapped[list[DnsRecord]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    technologies: Mapped[list[Technology]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    findings: Mapped[list[Finding]] = relationship(back_populates="asset", cascade="all, delete-orphan")


class Service(Base):
    __tablename__ = "services"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_uuid)
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id"), nullable=False, index=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), default="tcp")
    service_name: Mapped[str] = mapped_column(String(100), default="")
    version: Mapped[str | None] = mapped_column(String(100))
    state: Mapped[str] = mapped_column(String(20), default="open")
    source: Mapped[str] = mapped_column(String(100), default="")
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id"), nullable=True)

    asset: Mapped[Asset] = relationship(back_populates="services")

    __table_args__ = (UniqueConstraint("asset_id", "protocol", "port", name="uq_service"),)


class DnsRecord(Base):
    __tablename__ = "dns_records"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_uuid)
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id"), nullable=False, index=True)
    record_type: Mapped[str] = mapped_column(String(10), nullable=False)  # A AAAA CNAME MX NS TXT
    value: Mapped[str] = mapped_column(String(1000), nullable=False)
    ttl: Mapped[int | None] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(100), default="")
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id"), nullable=True)

    asset: Mapped[Asset] = relationship(back_populates="dns_records")


class Technology(Base):
    __tablename__ = "technologies"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_uuid)
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[str | None] = mapped_column(String(100))
    confidence: Mapped[float] = mapped_column(Float, default=0.5)  # 0.0 - 1.0
    source: Mapped[str] = mapped_column(String(100), default="")
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id"), nullable=True)

    asset: Mapped[Asset] = relationship(back_populates="technologies")

    __table_args__ = (UniqueConstraint("asset_id", "name", "source", name="uq_technology"),)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_uuid)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id"), nullable=False, index=True)
    finding_type: Mapped[str] = mapped_column(String(100), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(100), default="")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    priority: Mapped[int] = mapped_column(Integer, default=0)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    asset: Mapped[Asset] = relationship(back_populates="findings")

    __table_args__ = (UniqueConstraint("project_id", "finding_type", "asset_id", "value", name="uq_finding"),)


class Relationship(Base):
    __tablename__ = "relationships"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_uuid)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    src_asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id"), nullable=False, index=True)
    dst_asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id"), nullable=True, index=True)
    # kept even when dst is not an asset; RESOLVES_TO, CNAME_TO, SUBDOMAIN_OF, ...
    dst_value: Mapped[str] = mapped_column(String(1000), nullable=False)
    rel_type: Mapped[str] = mapped_column(String(50), nullable=False)
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_uuid)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    profile: Mapped[str] = mapped_column(String(50), default="standard")
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.QUEUED, index=True)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    stats: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    stop_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    project: Mapped[Project] = relationship(back_populates="scans")
    tasks: Mapped[list[ScanTask]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class ScanTask(Base):
    __tablename__ = "scan_tasks"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=new_uuid)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    module: Mapped[str] = mapped_column(String(50), nullable=False)  # stage.adapter name
    status: Mapped[TaskStatus] = mapped_column(Enum(TaskStatus), default=TaskStatus.PENDING)
    detail: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    scan: Mapped[Scan] = relationship(back_populates="tasks")
