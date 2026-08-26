"""Pipeline integration tests with fake adapters (no network, no binaries)."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

import plugins.registry as registry
from backend.models.entities import (
    Asset,
    AssetType,
    Relationship,
    Scan,
    ScanStatus,
    ScanTask,
    TaskStatus,
    Technology,
)
from engine import pipeline
from engine.scope import ScopeChecker
from plugins.base import AdapterResult
from tests.conftest import make_scan


class FakeSubdomainAdapter:
    stage = "subdomain"

    def __init__(self, config=None):
        self.config = config or {}

    def name(self):
        return "fake-subfinder"

    def version(self):
        return "0.0-test"

    def check_installation(self):
        return True

    async def run(self, ctx):
        for host in ("api.example.com", "dev.example.com", "admin.example.com"):
            ctx.add_hostname(host, source=self.name())
        return AdapterResult(adapter=self.name(), stage=self.stage, items=3)


class FakeDnsAdapter:
    stage = "dns"

    def __init__(self, config=None):
        self.config = config or {}

    def name(self):
        return "fake-dns"

    def version(self):
        return "0.0-test"

    def check_installation(self):
        return True

    async def run(self, ctx):
        ctx.add_dns_record("api.example.com", "A", "1.2.3.4", ttl=300, source=self.name())
        ctx.add_ip("1.2.3.4", hostname="api.example.com", source=self.name())
        ctx.add_dns_record("dev.example.com", "A", "1.2.3.4", source=self.name())
        ctx.add_url("https://api.example.com/", source=self.name(), status=200)
        ctx.add_technology("api.example.com", "nginx", version="1.24",
                           confidence=0.6, source="fake-evidence")
        return AdapterResult(adapter=self.name(), stage=self.stage, items=5)


class FailingAdapter:
    stage = "ports"

    def __init__(self, config=None):
        self.config = config or {}

    def name(self):
        return "failing-scanner"

    def version(self):
        return "0.0-test"

    def check_installation(self):
        return True

    async def run(self, ctx):
        raise RuntimeError("simulated tool crash")


@pytest.fixture()
def patched_registry(monkeypatch):
    """Only fake adapters run during pipeline tests."""
    fakes = {"subdomain": [FakeSubdomainAdapter], "dns": [FakeDnsAdapter],
             "ports": [FailingAdapter]}

    def factory(stage, cfg=None):
        cfg = cfg or {}
        return [cls(config=cfg.get(stage)) for cls in fakes.get(stage, [])]

    monkeypatch.setattr(registry, "get_adapters", factory)
    return fakes


def test_partial_failure_does_not_abort_scan(session_factory, project_id,
                                             patched_registry):
    scan_id = make_scan(session_factory, project_id)
    status = pipeline.run_scan(session_factory, scan_id)

    # ports adapter fails on purpose -> PARTIAL; other modules still succeeded
    assert status == ScanStatus.PARTIAL

    with session_factory() as s:
        assets = {a.value: a for a in s.scalars(select(Asset)).all()}
        assert {"api.example.com", "dev.example.com", "admin.example.com",
                "1.2.3.4", "https://api.example.com/"} <= set(assets)

        db_scan = s.get(Scan, scan_id)
        task_modules = {t.module: t.status for t in s.query(ScanTask).all()}
        assert task_modules["subdomain"] == TaskStatus.SUCCESS
        assert task_modules["dns"] == TaskStatus.SUCCESS
        assert task_modules["ports"] == TaskStatus.FAILED
        assert db_scan.error and "failing-scanner" in db_scan.error


def test_scope_enforcement_and_correlation(session_factory, project_id,
                                           patched_registry):
    scan_id = make_scan(session_factory, project_id)
    pipeline.run_scan(session_factory, scan_id)

    with session_factory() as s:
        assets = {a.value: a for a in s.scalars(select(Asset)).all()}

        # out-of-scope discoveries are stored (passive) but flagged
        assert assets["admin.example.com"].scope_status == "OUT_OF_SCOPE"
        assert assets["api.example.com"].scope_status == "IN_SCOPE"
        assert assets["1.2.3.4"].asset_type == AssetType.IP

        rel_types = {r.rel_type for r in s.scalars(select(Relationship)).all()}
        assert {"RESOLVES_TO", "SUBDOMAIN_OF", "HOSTS_URL"} <= rel_types

        # transparent scoring on a dev-labeled host
        dev = assets["dev.example.com"]
        kinds = {r["reason"] for r in dev.priority_reasons}
        assert "development_staging_indicator" in kinds
        assert dev.priority_score > assets["admin.example.com"].priority_score or \
            dev.priority_score > 0

        stats = db_scan_stats(s, scan_id)
        assert stats["hostname_count"] == 4  # target + api + dev + admin
        assert stats["ips"] == 1
        assert stats["urls"] == 1


def db_scan_stats(session, scan_id):
    return session.get(Scan, scan_id).stats


def test_json_columns_persist_across_sessions(session_factory, project_id,
                                              patched_registry):
    """JSON mutations must be visible from a *fresh* session (PostgreSQL safety)."""
    scan_id = make_scan(session_factory, project_id)
    pipeline.run_scan(session_factory, scan_id)
    # second pass exercises the dedup/update path on existing rows
    scan2 = make_scan(session_factory, project_id)
    pipeline.run_scan(session_factory, scan2)

    with session_factory() as s:
        scan = s.get(Scan, scan_id)
        assert (scan.config or {}).get("resolved", {}).get("stages")  # config["resolved"] persisted

        api = s.scalar(select(Asset).where(Asset.value == "api.example.com"))
        assert set(api.extra_data.get("sources", [])) >= {"fake-subfinder", "fake-dns"}

        ip = s.scalar(select(Asset).where(Asset.value == "1.2.3.4"))
        assert "api.example.com" in ip.extra_data.get("hostnames", [])

    with session_factory() as s:
        scan_b = s.get(Scan, scan2)
        assert (scan_b.stats or {}).get("hostname_count") == 4
        diff = (scan_b.stats or {}).get("diff_vs_previous")
        assert diff is not None and diff["added"] == []  # second scan discovers nothing new


def test_duplicate_technologies_not_duplicated_on_rerun(session_factory,
                                                        project_id, patched_registry):
    pipeline.run_scan(session_factory, make_scan(session_factory, project_id))
    with session_factory() as s:
        first = s.scalar(select(func.count(Technology.id)))
    assert first > 0

    pipeline.run_scan(session_factory, make_scan(session_factory, project_id))
    with session_factory() as s:
        second = s.scalar(select(func.count(Technology.id)))
    assert first == second


def test_active_scan_gate_excludes_unknown_and_denied():
    checker = ScopeChecker([("example.com", "ALLOW"), ("10.0.0.99", "DENY")])
    candidates = [
        {"value": "1.2.3.4"},    # UNKNOWN
        {"value": "10.0.0.99"},  # DENY
        {"value": "203.0.113.7"},
    ]
    allowed = [r["value"] for r in candidates if checker.allows_active_scan(r["value"])]
    assert allowed == []


def test_stop_requested_yields_stopped_scan(session_factory, project_id,
                                            patched_registry):
    scan_id = make_scan(session_factory, project_id)
    with session_factory() as s:
        s.get(Scan, scan_id).stop_requested = True
        s.commit()
    status = pipeline.run_scan(session_factory, scan_id)
    assert status == ScanStatus.STOPPED


def test_nmap_scope_gate_in_run(monkeypatch, project_id):
    """NmapAdapter.run must only pass IN_SCOPE IPs to build_command."""
    import asyncio
    import uuid

    from engine.context import ScanContext
    from plugins.ports.nmap_adapter import NmapAdapter

    checker = ScopeChecker([("192.168.0.0/16", "ALLOW"), ("bad.example.com", "DENY")])
    ctx = ScanContext(project_id=project_id, scan_id=uuid.uuid4(), scope=checker)
    ctx.add_ip("192.168.1.10", source="test", hostname="ok.example.com")
    ctx.add_ip("203.0.113.9", source="test", hostname="unknown.example.com")
    ctx.add_ip("192.168.1.66", source="test", hostname="bad.example.com")

    built = {}
    adapter = NmapAdapter(config={})
    monkeypatch.setattr(NmapAdapter, "check_installation", lambda self: True)
    monkeypatch.setattr(NmapAdapter, "build_command",
                        lambda self, t, p: built.setdefault("targets", list(t)))

    async def fake_execute(self, cmd):
        return 0, b"<nmaprun></nmaprun>"
        # closed ports only -> no services persisted

    monkeypatch.setattr(NmapAdapter, "execute", fake_execute)

    result = asyncio.run(adapter.run(ctx))
    assert built["targets"] == ["192.168.1.10"]
    assert result.raw_summary["skipped_out_of_scope"] == 2
