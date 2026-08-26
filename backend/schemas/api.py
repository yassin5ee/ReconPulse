"""Pydantic schemas for API request/response validation."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------- projects


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = ""


class ScopeRuleIn(BaseModel):
    pattern: str = Field(min_length=1, max_length=500)
    rule_type: str = Field(pattern="^(ALLOW|DENY)$")
    comment: str = ""


class ScopeRuleOut(ScopeRuleIn):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID


class ProjectUpdate(BaseModel):
    description: str | None = None


class TargetIn(BaseModel):
    value: str = Field(min_length=1, max_length=500)
    target_type: str = Field(default="domain", pattern="^(domain|ip|cidr|range)$")


class TargetOut(TargetIn):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    description: str
    created_at: datetime


# ---------------------------------------------------------------- scans


class ScanCreate(BaseModel):
    profile: str = Field(default="standard", pattern="^(quick|standard|full|custom)$")
    config: dict[str, Any] = Field(default_factory=dict)


class ScanTaskOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    module: str
    status: str
    detail: str | None
    duration_ms: int | None


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    project_id: uuid.UUID
    profile: str
    status: str
    config: dict[str, Any]
    stats: dict[str, Any]
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None


# ---------------------------------------------------------------- assets & findings


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    asset_type: str
    value: str
    scope_status: str
    priority_score: int
    priority_reasons: list[Any] = []
    first_seen: datetime
    last_seen: datetime
    extra_data: dict[str, Any] = Field(default_factory=dict)


class ServiceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    port: int
    protocol: str
    service_name: str
    version: str | None
    state: str
    source: str


class TechnologyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    name: str
    version: str | None
    confidence: float
    source: str


class DnsRecordOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    record_type: str
    value: str
    ttl: int | None
    source: str


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    finding_type: str
    value: str
    source: str
    confidence: float
    priority: int
    reasons: list[Any] = []


class AssetDetail(AssetOut):
    services: list[ServiceOut] = []
    technologies: list[TechnologyOut] = []
    dns_records: list[DnsRecordOut] = []
    findings: list[FindingOut] = []


# ---------------------------------------------------------------- graph / stats / export


class GraphNode(BaseModel):
    id: str
    label: str
    node_type: str
    scope_status: str = "UNKNOWN"
    score: int = 0


class GraphEdge(BaseModel):
    src: str
    dst: str
    rel_type: str


class GraphOut(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class Statistics(BaseModel):
    assets: int = 0
    domains: int = 0
    subdomains: int = 0
    ips: int = 0
    urls: int = 0
    open_ports: int = 0
    technologies: int = 0
    findings: int = 0
    high_priority_assets: int = 0
    scans_total: int = 0
    last_scan_status: str | None = None


class ScanDiff(BaseModel):
    scan_a: uuid.UUID
    scan_b: uuid.UUID
    added: list[str]
    removed: list[str]
