"""ReconPulse CLI (Typer).

Shares the database and services with the API; `scan start` enqueues a scan
that a running worker picks up. Use `--wait` to block until completion.
"""

from __future__ import annotations

import time
import uuid

import httpx
import typer
from rich.console import Console
from rich.table import Table

from backend.core.config import get_settings
from backend.database.session import SessionLocal
from backend.models.entities import (
    Asset,
    AssetType,
    Finding,
    Project,
    RuleType,
    Scan,
    ScanStatus,
    ScopeRule,
    Target,
)
from services import export_service

app = typer.Typer(help="ReconPulse — Know your target before you attack.",
                  no_args_is_help=True, add_completion=False)
project_app = typer.Typer(help="Manage projects", no_args_is_help=True)
target_app = typer.Typer(help="Manage targets", no_args_is_help=True)
scan_app = typer.Typer(help="Manage scans", no_args_is_help=True)
asset_app = typer.Typer(help="Inspect assets", no_args_is_help=True)
finding_app = typer.Typer(help="Inspect findings", no_args_is_help=True)
report_app = typer.Typer(help="Export reports", no_args_is_help=True)
scope_app = typer.Typer(help="Manage scope rules", no_args_is_help=True)
app.add_typer(project_app, name="project")
app.add_typer(target_app, name="target")
app.add_typer(scan_app, name="scan")
app.add_typer(asset_app, name="asset")
app.add_typer(finding_app, name="finding")
app.add_typer(report_app, name="report")
app.add_typer(scope_app, name="scope")

console = Console()
err = Console(stderr=True)


def _session():
    return SessionLocal()


def _resolve_project(session, name_or_id: str) -> Project:
    project = session.query(Project).filter(Project.name == name_or_id).first()
    if not project:
        try:
            project = session.get(Project, uuid.UUID(name_or_id))
        except ValueError:
            project = None
    if not project:
        err.print(f"[red]Project not found:[/] {name_or_id}")
        raise typer.Exit(1)
    return project


# ----------------------------------------------------------------- project


@project_app.command("create")
def project_create(name: str, description: str = ""):
    """Create a new reconnaissance project."""
    with _session() as s:
        if s.query(Project).filter(Project.name == name).first():
            err.print(f"[red]Project already exists:[/] {name}")
            raise typer.Exit(1)
        p = Project(name=name, description=description)
        s.add(p)
        s.commit()
        console.print(f"[green]Created project[/] {name} ({p.id})")


@project_app.command("list")
def project_list():
    with _session() as s:
        table = Table(title="Projects")
        table.add_column("Name")
        table.add_column("ID")
        table.add_column("Targets")
        for p in s.query(Project).all():
            table.add_row(p.name, str(p.id), str(len(p.targets)))
        console.print(table)


# ----------------------------------------------------------------- target / scope


@target_app.command("add")
def target_add(project: str, value: str, target_type: str = "domain"):
    """Add an authorized target and auto-seed its ALLOW scope rule."""
    with _session() as s:
        p = _resolve_project(s, project)
        from backend.api.routes.projects import _validate_target

        normalized = _validate_target(value, target_type)
        s.add(Target(project_id=p.id, value=normalized, target_type=target_type))
        # seed exact (+ wildcard for domains so discovered subdomains stay in scope)
        patterns = {normalized}
        if target_type == "domain":
            patterns.add(f"*.{normalized}")
        for pat in patterns:
            s.add(ScopeRule(project_id=p.id, pattern=pat,
                            rule_type=RuleType.ALLOW, comment="added with target"))
        s.commit()
        console.print(f"[green]Target added[/] {normalized} -> {p.name}")


@scope_app.command("add")
def scope_add(project: str, pattern: str,
              rule_type: str = typer.Option(..., help="ALLOW or DENY"),
              comment: str = ""):
    """Add a scope rule (e.g. *.example.com ALLOW, admin.example.com DENY)."""
    if rule_type.upper() not in ("ALLOW", "DENY"):
        err.print("[red]rule_type must be ALLOW or DENY[/]")
        raise typer.Exit(1)
    with _session() as s:
        p = _resolve_project(s, project)
        s.add(ScopeRule(project_id=p.id, pattern=pattern.strip().lower(),
                        rule_type=RuleType(rule_type.upper()), comment=comment))
        s.commit()
        console.print(f"[green]Scope rule added:[/] {rule_type.upper()} {pattern}")


@scope_app.command("check")
def scope_check(project: str, value: str):
    """Evaluate how a hostname/IP would be classified by the current scope."""
    with _session() as s:
        p = _resolve_project(s, project)
        from engine.scope import checker_from_project

        checker = checker_from_project(p.scope_rules)
        status = checker.classify(value)
        color = {"IN_SCOPE": "green", "OUT_OF_SCOPE": "red"}.get(status.value, "yellow")
        console.print(f"{value} -> [{color}]{status.value}[/]")


# ----------------------------------------------------------------- scan


@scan_app.command("start")
def scan_start(project: str, profile: str = "standard",
               wait: bool = typer.Option(False, "--wait", help="Block until the scan finishes."),
               timeout: int = 3600):
    """Queue a scan; requires a running reconpulse-worker."""
    with _session() as s:
        p = _resolve_project(s, project)
        scan = Scan(project_id=p.id, profile=profile)
        s.add(scan)
        s.commit()
        console.print(f"[green]Scan queued[/] {scan.id} (profile={profile})")
    if wait:
        console.print("Waiting for completion… (Ctrl+C to detach)")
        deadline = time.time() + timeout
        while time.time() < deadline:
            with _session() as s2:
                current = s2.get(Scan, scan.id)
                if current.status not in (ScanStatus.QUEUED, ScanStatus.RUNNING):
                    _print_scan(current)
                    raise typer.Exit(0 if current.status != ScanStatus.FAILED else 1)
            time.sleep(2)
        err.print("[red]Timed out waiting for scan.[/]")
        raise typer.Exit(1)


@scan_app.command("status")
def scan_status(scan_id: str):
    with _session() as s:
        scan = s.get(Scan, uuid.UUID(scan_id))
        if not scan:
            err.print("[red]Scan not found.[/]")
            raise typer.Exit(1)
        _print_scan(scan)


@scan_app.command("stop")
def scan_stop(scan_id: str):
    settings = get_settings()
    try:
        resp = httpx.post(f"http://{settings.api_host}:{settings.api_port}"
                          f"/scans/{scan_id}/stop", timeout=10)
        resp.raise_for_status()
    except Exception:
        with _session() as s:
            scan = s.get(Scan, uuid.UUID(scan_id))
            if not scan:
                err.print("[red]Scan not found.[/]")
                raise typer.Exit(1) from None
            scan.stop_requested = True
            if scan.status == ScanStatus.QUEUED:
                scan.status = ScanStatus.STOPPED
            s.commit()
    console.print(f"[yellow]Stop requested[/] {scan_id}")


@scan_app.command("list")
def scan_list(project: str):
    with _session() as s:
        p = _resolve_project(s, project)
        table = Table(title=f"Scans — {p.name}")
        for col in ("ID", "Profile", "Status", "Hostnames", "Started"):
            table.add_column(col)
        for sc in s.query(Scan).filter(Scan.project_id == p.id).order_by(Scan.started_at):
            stats = sc.stats or {}
            table.add_row(str(sc.id), sc.profile, sc.status.value,
                          str(stats.get("hostname_count", "-")),
                          str(sc.started_at))
        console.print(table)


def _print_scan(scan: Scan) -> None:
    console.print(f"Scan {scan.id}: [{ 'green' if scan.status.value=='completed' else 'yellow'}]"
                  f"{scan.status.value}[/] profile={scan.profile}")
    if scan.error:
        err.print(f"[red]{scan.error}[/]")
    for task in sorted(scan.tasks, key=lambda t: t.started_at or 0):
        mark = {"success": "✔", "failed": "✘", "skipped": "–",
                "pending": "…", "running": "…"}.get(task.status.value, "?")
        dur = f"{task.duration_ms}ms" if task.duration_ms is not None else ""
        console.print(f"  {mark} {task.module:<12} {task.status.value:<8} {dur}")


# ----------------------------------------------------------------- asset / finding


@asset_app.command("list")
def asset_list(project: str, asset_type: str | None = None,
               min_score: int = 0):
    with _session() as s:
        p = _resolve_project(s, project)
        q = s.query(Asset).filter(Asset.project_id == p.id)
        if asset_type:
            q = q.filter(Asset.asset_type == AssetType(asset_type))
        q = q.filter(Asset.priority_score >= min_score)
        table = Table(title=f"Assets — {p.name}")
        for col in ("Value", "Type", "Scope", "Priority", "Ports"):
            table.add_column(col)
        for a in q.order_by(Asset.priority_score.desc()).limit(200):
            ports = ",".join(str(sv.port) for sv in a.services) or ""
            table.add_row(a.value[:60], a.asset_type.value, a.scope_status.value,
                          str(a.priority_score), ports)
        console.print(table)


@asset_app.command("show")
def asset_show(project: str, value: str):
    with _session() as s:
        p = _resolve_project(s, project)
        asset = s.query(Asset).filter(Asset.project_id == p.id, Asset.value == value).first()
        if not asset:
            err.print("[red]Asset not found.[/]")
            raise typer.Exit(1)
        console.print(f"[bold]{asset.value}[/] ({asset.asset_type.value}, "
                      f"{asset.scope_status.value}, priority {asset.priority_score})")
        for reason in asset.priority_reasons or []:
            console.print(f"  · {reason.get('reason')} (+{reason.get('points', 0)})")
        for rec in asset.dns_records:
            console.print(f"  DNS {rec.record_type} -> {rec.value}")
        for svc in asset.services:
            console.print(f"  PORT {svc.port}/{svc.protocol} {svc.service_name} {svc.version or ''}")
        for tech in asset.technologies:
            console.print(f"  TECH {tech.name} {tech.version or ''} "
                          f"(confidence {tech.confidence:.0%}, source {tech.source})")


@finding_app.command("list")
def finding_list(project: str):
    with _session() as s:
        p = _resolve_project(s, project)
        table = Table(title=f"Findings — {p.name}")
        for col in ("Type", "Value", "Priority", "Source"):
            table.add_column(col)
        for f in (s.query(Finding).filter(Finding.project_id == p.id)
                  .order_by(Finding.priority.desc()).limit(200)):
            table.add_row(f.finding_type, f.value[:60], str(f.priority), f.source)
        console.print(table)


# ----------------------------------------------------------------- report


@report_app.command("export")
def report_export(project: str, output: str,
                  format: str | None = typer.Option(None, help="json|csv|markdown|html")):
    """Export a project report. Format inferred from --output extension when omitted."""
    fmt = format or output.rsplit(".", 1)[-1].lower()
    mapping = {"json": export_service.export_json, "csv": export_service.export_csv,
               "md": export_service.export_markdown,
               "markdown": export_service.export_markdown,
               "html": export_service.export_html}
    exporter = mapping.get(fmt)
    if not exporter:
        err.print(f"[red]Unknown format '{fmt}'. Use json, csv, markdown or html.[/]")
        raise typer.Exit(1)
    with _session() as s:
        p = _resolve_project(s, project)
        content = exporter(s, p.id)
    with open(output, "wb") as fh:
        fh.write(content)
    console.print(f"[green]Report written[/] {output} ({len(content)} bytes)")


if __name__ == "__main__":
    app()
