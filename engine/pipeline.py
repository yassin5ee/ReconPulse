"""Scan pipeline: stage execution, persistence, dedup, scoring, stats.

Guarantees:
- a failing module degrades the scan to PARTIAL, never crashes other modules
- OUT_OF_SCOPE / UNKNOWN assets are stored but never actively scanned
- every persisted item is attributed to its source adapter
- scans are reproducible: config, profile, tool versions and stats are stored
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

import plugins.registry as registry  # noqa: F401  ensures adapters register
from backend.core.logging import log_event
from backend.models.entities import (
    Asset,
    AssetType,
    DnsRecord,
    Relationship,
    Scan,
    ScanStatus,
    ScanTask,
    ScopeRule,
    Service,
    Target,
    TaskStatus,
    Technology,
)
from engine import correlation, profiles, scoring
from engine.context import ScanContext
from engine.scope import ScopeChecker, is_ip
from plugins.base import gather_adapters

logger = logging.getLogger("reconpulse.pipeline")


class StopRequested(Exception):
    pass


def _check_stop(session: Session, scan_id: uuid.UUID) -> None:
    session.expire_all()
    scan = session.get(Scan, scan_id)
    if scan is None or scan.stop_requested:
        raise StopRequested()


def run_scan(session_factory, scan_id: uuid.UUID) -> ScanStatus:
    """Entry point used by the worker. Owns its sessions/transactions."""
    session = session_factory()
    try:
        return asyncio_run(_run_pipeline(session, session_factory, scan_id))
    finally:
        session.close()


def asyncio_run(coro):  # thin wrapper for testability
    import asyncio
    return asyncio.run(coro)


async def _run_pipeline(session: Session, session_factory, scan_id: uuid.UUID) -> ScanStatus:
    started = time.monotonic()
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise ValueError(f"scan {scan_id} not found")

    log_event(logger, "info", "scan_started", scan_id=str(scan_id),
              project=str(scan.project_id), profile=scan.profile)
    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.now(UTC)
    session.commit()

    plan = profiles.resolve_profile(scan.profile, scan.config)
    # reassign + flush immediately: JSON columns must be replaced rather than
    # mutated, and _check_stop() expires objects between stages.
    scan.config = {**scan.config, "resolved": plan}
    session.commit()
    project_id = scan.project_id

    rules = [(r.pattern, r.rule_type.value) for r in session.scalars(
        select(ScopeRule).where(ScopeRule.project_id == project_id))]
    targets = [t.value.lower() for t in session.scalars(
        select(Target).where(Target.project_id == project_id))]

    ctx = ScanContext(project_id=project_id, scan_id=scan_id,
                      scope=ScopeChecker(rules), logger=logger)
    ctx.inputs["targets"] = targets
    ctx.inputs["scan_profile"] = plan["ports_profile"]
    # authorized targets are themselves assets of the surface
    for t in targets:
        ctx.add_hostname(t, source="target")

    failures: list[str] = []
    task_rows: dict[str, ScanTask] = {}
    try:
        for stage in plan["stages"]:
            _check_stop(session, scan_id)
            adapters = registry.get_adapters(stage, scan.config.get("adapters", {}))
            task = ScanTask(scan_id=scan_id, module=stage, status=TaskStatus.RUNNING,
                            started_at=datetime.now(UTC))
            session.add(task)
            session.commit()
            task_rows[stage] = task

            t0 = time.monotonic()
            results = await gather_adapters(ctx, adapters)
            duration_ms = int((time.monotonic() - t0) * 1000)

            stage_errors = [f"{r.adapter}: {r.error}" for r in results if not r.success]
            failures.extend(f"{stage}/{e}" for e in stage_errors)
            if not results:
                task.status = TaskStatus.SKIPPED
            elif len(stage_errors) == len(results):
                task.status = TaskStatus.FAILED
            else:
                task.status = TaskStatus.SUCCESS
            task.detail = "; ".join(stage_errors)[:1000] or f"{sum(r.items for r in results)} items"
            task.duration_ms = duration_ms
            task.finished_at = datetime.now(UTC)

            persist_context(session, ctx, scan_id)
            log_event(logger, "info", "module_finished", scan_id=str(scan_id),
                      module=stage, duration=f"{duration_ms}ms",
                      errors=len(stage_errors))
            session.commit()
    except StopRequested:
        scan.status = ScanStatus.STOPPED
        scan.finished_at = datetime.now(UTC)
        _finalize(session, ctx, scan, failures)
        return scan.status

    # technology stage needs bodies captured during http probing; heuristic
    # adapter reads ctx.http_results directly (bodies are not persisted).
    _finalize(session, ctx, scan, failures)
    scan.status = ScanStatus.PARTIAL if failures else ScanStatus.COMPLETED
    scan.finished_at = datetime.now(UTC)
    session.commit()
    total_s = round(time.monotonic() - started, 1)
    log_event(logger, "info", "scan_finished", scan_id=str(scan_id),
              status=scan.status.value, duration=f"{total_s}s")
    return scan.status


def _finalize(session: Session, ctx: ScanContext, scan: Scan, failures: list[str]) -> None:
    """Correlate, score, diff against previous scan, close out the scan."""
    persist_context(session, ctx, scan.id)
    correlation.build_relationships(session, scan.project_id, scan.id)
    score_project_assets(session, scan.project_id, new_since=scan.started_at)
    scan.stats = _compute_stats(session, scan)
    if failures:
        scan.error = "failed modules: " + ", ".join(failures)[:2000]
    session.commit()


def persist_context(session: Session, ctx: ScanContext, scan_id: uuid.UUID) -> None:
    """Upsert normalized context items into the database with dedup + scoping."""
    def get_asset(value: str, asset_type: AssetType, source: str = "",
                  meta: dict | None = None) -> Asset:
        asset_type_resolved = _resolve_asset_type(value, asset_type, ctx)
        existing = session.scalar(
            select(Asset).where(
                Asset.project_id == ctx.project_id,
                Asset.asset_type == asset_type_resolved,
                Asset.value == value))
        if existing:
            existing.last_seen = datetime.now(UTC)
            sources = list(existing.extra_data.get("sources", []))
            if source and source not in sources:
                sources.append(source)
            merged = {**(existing.extra_data or {}), "sources": sources, **(meta or {})}
            existing.extra_data = merged  # reassignment keeps JSON change tracking
            return existing
        asset = Asset(
            project_id=ctx.project_id,
            asset_type=asset_type_resolved,
            value=value,
            scope_status=ctx.scope.classify(value),
            extra_data={"sources": [source] if source else [], **(meta or {})},
        )
        session.add(asset)
        session.flush()
        log_event(logger, "info", "asset_persisted", scan_id=str(scan_id),
                  type=asset.asset_type.value, value=value,
                  scope=asset.scope_status.value)
        return asset

    for rec in ctx.hostnames:
        get_asset(rec["value"], AssetType.SUBDOMAIN, source=rec["source"])

    for rec in ctx.ips:
        asset = get_asset(rec["value"], AssetType.IP, source=rec["source"])
        if rec["hostnames"]:
            known = list(asset.extra_data.get("hostnames", []))
            for h in rec["hostnames"]:
                if h and h not in known:
                    known.append(h)
            asset.extra_data = {**(asset.extra_data or {}), "hostnames": known}

    for rec in ctx.urls:
        get_asset(rec["value"], AssetType.URL, source=rec["source"], meta=dict(rec["meta"]))

    for http in ctx.http_results:
        asset = get_asset(http["url"], AssetType.URL, source=http["source"])
        asset.extra_data = {
            **(asset.extra_data or {}),
            "status_code": http["status_code"],
            "title": http["title"],
            "headers": http["headers"],
            "content_length": http["content_length"],
            "final_url": http["final_url"],
            "tls": http["tls"],
        }

    for svc in ctx.services:
        asset = get_asset(svc["host"], AssetType.IP if is_ip(svc["host"]) else AssetType.SUBDOMAIN)
        existing = session.scalar(
            select(Service).where(Service.asset_id == asset.id,
                                  Service.protocol == svc["protocol"],
                                  Service.port == svc["port"]))
        if not existing:
            session.add(Service(asset_id=asset.id, port=svc["port"],
                                protocol=svc["protocol"], service_name=svc["service_name"],
                                version=svc["version"], state=svc["state"],
                                source=svc["source"], scan_id=scan_id))

    for dns in ctx.dns_records:
        asset = get_asset(dns["hostname"], AssetType.SUBDOMAIN, source=dns["source"])
        exists = session.scalar(
            select(DnsRecord).where(DnsRecord.asset_id == asset.id,
                                    DnsRecord.record_type == dns["record_type"],
                                    DnsRecord.value == dns["value"]))
        if not exists:
            session.add(DnsRecord(asset_id=asset.id, record_type=dns["record_type"],
                                  value=dns["value"], ttl=dns["ttl"],
                                  source=dns["source"], scan_id=scan_id))

    for tech in ctx.technologies:
        asset = get_asset(tech["host"], AssetType.SUBDOMAIN, source=tech["source"])
        exists = session.scalar(
            select(Technology).where(Technology.asset_id == asset.id,
                                     Technology.name == tech["name"],
                                     Technology.source == tech["source"]))
        if not exists:
            session.add(Technology(asset_id=asset.id, name=tech["name"],
                                   version=tech["version"], confidence=tech["confidence"],
                                   source=tech["source"], scan_id=scan_id))
    session.flush()


def _resolve_asset_type(value: str, requested: AssetType, ctx: ScanContext) -> AssetType:
    if requested != AssetType.SUBDOMAIN:
        return requested
    if value in ctx.inputs.get("targets", []):
        return AssetType.DOMAIN
    return AssetType.SUBDOMAIN


def score_project_assets(session: Session, project_id: uuid.UUID,
                         new_since: datetime | None = None) -> None:
    assets = session.scalars(select(Asset).where(Asset.project_id == project_id)).all()
    rel_counts = _relationship_counts(session, project_id)

    for asset in assets:
        open_ports = [s.port for s in asset.services]
        techs = list(asset.technologies)
        facts = scoring.AssetFacts(
            value=asset.value,
            resolves_public_ip=_has_public_ip(session, asset),
            open_ports=open_ports,
            dev_indicator=scoring.dev_indicator_for(asset.value),
            live_http=(asset.asset_type == AssetType.URL
                       and (asset.extra_data.get("status_code") or 0) < 500),
            technologies=len(techs),
            relationship_count=rel_counts.get(asset.id, 0),
            newly_discovered=bool(new_since and asset.first_seen >= new_since),
            low_confidence_only=bool(techs) and all(t.confidence < 0.5 for t in techs),
        )
        score, reasons = scoring.score_asset(facts)
        asset.priority_score = score
        asset.priority_reasons = reasons


def _relationship_counts(session: Session, project_id: uuid.UUID) -> dict:
    rows = session.query(Relationship.src_asset_id).filter(
        Relationship.project_id == project_id).all()
    counts: dict = {}
    for (src,) in rows:
        counts[src] = counts.get(src, 0) + 1
    return counts


def _has_public_ip(session: Session, asset: Asset) -> bool:
    import ipaddress

    from engine.normalization import is_valid_ip
    candidates: list[str] = []
    if is_valid_ip(asset.value):
        candidates.append(asset.value)
    for rec in asset.dns_records:
        if rec.record_type in ("A", "AAAA") and is_valid_ip(rec.value):
            candidates.append(rec.value)
    for candidate in candidates:
        addr = ipaddress.ip_address(candidate)
        if not addr.is_private and not addr.is_loopback and not addr.is_reserved:
            return True
    return False


def _compute_stats(session: Session, scan: Scan) -> dict[str, Any]:
    pid = scan.project_id
    assets = session.scalars(select(Asset).where(Asset.project_id == pid)).all()
    stats: dict[str, Any] = {
        "assets": len(assets),
        "domains": sum(1 for a in assets if a.asset_type == AssetType.DOMAIN),
        "subdomains": sum(1 for a in assets if a.asset_type == AssetType.SUBDOMAIN),
        "ips": sum(1 for a in assets if a.asset_type == AssetType.IP),
        "urls": sum(1 for a in assets if a.asset_type == AssetType.URL),
        "open_ports": sum(len(a.services) for a in assets),
        "technologies": sum(len(a.technologies) for a in assets),
        "high_priority_assets": sum(1 for a in assets
                                    if a.priority_score >= scoring.high_priority_threshold()),
    }
    prev = session.scalar(
        select(Scan).where(
            Scan.project_id == pid, Scan.id != scan.id,
            Scan.finished_at.is_not(None),
            Scan.started_at < (scan.started_at or datetime.now(UTC)))
        .order_by(Scan.started_at.desc()))
    current_hostnames = {a.value for a in assets
                         if a.asset_type in (AssetType.DOMAIN, AssetType.SUBDOMAIN)}
    stats["hostname_count"] = len(current_hostnames)
    stats["hostname_set"] = sorted(current_hostnames)
    if prev:
        stats["diff_vs_previous"] = _diff_stats(prev, current_hostnames)
    return stats


def _diff_stats(prev: Scan, current_hostnames: set[str]) -> dict[str, Any]:
    """Hostname sets are snapshotted per scan at completion time."""
    prev_set: set[str] = set((prev.stats or {}).get("hostname_set", []))
    if not prev_set:
        return {"added": [], "removed": []}
    return {
        "added": sorted(current_hostnames - prev_set),
        "removed": sorted(prev_set - current_hostnames),
    }
