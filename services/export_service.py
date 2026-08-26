"""Report/export generation: JSON, CSV, Markdown, HTML.

Reports contain reconnaissance data only (assets, services, technologies,
findings, scope, scan config). Tool credentials/API keys are never stored in
project data and therefore never exported.
"""

from __future__ import annotations

import csv
import html
import io
import json
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models.entities import (
    Asset,
    Project,
    Scan,
    ScopeRule,
    Target,
)


def _collect(session: Session, project_id: uuid.UUID) -> dict[str, Any]:
    project = session.get(Project, project_id)
    assets = list(session.scalars(
        select(Asset).where(Asset.project_id == project_id)
        .order_by(Asset.priority_score.desc())))
    scans = list(session.scalars(select(Scan).where(Scan.project_id == project_id)))
    return {
        "project": {"id": str(project.id), "name": project.name,
                    "description": project.description},
        "scope": [{"pattern": r.pattern, "type": r.rule_type.value, "comment": r.comment}
                  for r in session.scalars(
                      select(ScopeRule).where(ScopeRule.project_id == project_id))],
        "targets": [t.value for t in session.scalars(
            select(Target).where(Target.project_id == project_id))],
        "scans": [{"id": str(s.id), "profile": s.profile, "status": s.status.value,
                   "started_at": str(s.started_at), "finished_at": str(s.finished_at),
                   "stats": s.stats} for s in scans],
        "assets": [_asset_dict(a) for a in assets],
    }


def _asset_dict(a: Asset) -> dict[str, Any]:
    return {
        "asset_type": a.asset_type.value, "value": a.value,
        "scope_status": a.scope_status.value, "priority_score": a.priority_score,
        "priority_reasons": a.priority_reasons or [],
        "sources": (a.extra_data or {}).get("sources", []),
        "status_code": (a.extra_data or {}).get("status_code"),
        "title": (a.extra_data or {}).get("title"),
        "first_seen": str(a.first_seen),
        "services": [{"port": s.port, "protocol": s.protocol,
                      "service": s.service_name, "version": s.version}
                     for s in a.services],
        "technologies": [{"name": t.name, "version": t.version,
                          "confidence": round(t.confidence, 2)}
                         for t in a.technologies],
    }


def export_json(session: Session, project_id: uuid.UUID) -> bytes:
    return json.dumps(_collect(session, project_id), indent=2, default=str).encode()


def export_csv(session: Session, project_id: uuid.UUID) -> bytes:
    data = _collect(session, project_id)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["asset_type", "value", "scope_status", "priority_score",
                     "ports", "technologies", "sources", "title"])
    for a in data["assets"]:
        ports = ";".join(f"{s['port']}/{s['protocol']}" for s in a["services"])
        techs = ";".join(t["name"] for t in a["technologies"])
        writer.writerow([a["asset_type"], a["value"], a["scope_status"],
                         a["priority_score"], ports, techs,
                         ";".join(a["sources"]), a["title"] or ""])
    return buf.getvalue().encode()


def export_markdown(session: Session, project_id: uuid.UUID) -> bytes:
    data = _collect(session, project_id)
    lines = [
        f"# ReconPulse Report — {html.escape(data['project']['name'])}",
        "",
        f"Generated: {uuid.uuid1().time}\n".replace(str(uuid.uuid1().time), "")[:0] or "",
        f"**Targets:** {', '.join(html.escape(t) for t in data['targets'])}",
        "",
        "## Scope",
        "| Pattern | Type | Comment |",
        "|---|---|---|",
    ]
    for r in data["scope"]:
        lines.append(f"| {html.escape(r['pattern'])} | {r['type']} "
                     f"| {html.escape(r['comment'])} |")
    lines += ["", "## Assets", ""]
    for a in data["assets"]:
        reasons = ", ".join(r.get("reason", "") for r in a["priority_reasons"])
        lines.append(
            f"- **{html.escape(a['value'])}** ({a['asset_type']}, "
            f"{a['scope_status']}, priority {a['priority_score']}"
            f"{' — ' + html.escape(reasons) if reasons else ''})"
        )
        for svc in a["services"]:
            ver = f" ({svc['version']})" if svc["version"] else ""
            lines.append(f"  - port {svc['port']}/{svc['protocol']} → {svc['service']}{ver}")
        for tech in a["technologies"]:
            v = f" {tech['version']}" if tech["version"] else ""
            lines.append(f"  - technology: {tech['name']}{v} (confidence {tech['confidence']})")
    return "\n".join(lines).encode()


_HTML_TEMPLATE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>ReconPulse — {{name}}</title>
<style>
 body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9;margin:2rem}
 h1,h2{color:#58a6ff}
 table{border-collapse:collapse;width:100%;margin:1rem 0}
 th,td{border:1px solid #30363d;padding:.4rem .6rem;text-align:left;font-size:.9rem}
 tr:nth-child(even){background:#161b22}
 .in-scope{color:#3fb950}.out-of-scope{color:#f85149}.unknown{color:#d29922}
 .badge{display:inline-block;padding:.05rem .5rem;border-radius:10px;border:1px solid #30363d;
 margin-right:.3rem}
</style></head><body>
<h1>ReconPulse — {{name}}</h1>
<p>Authorized-use only report. Targets: <b>{{targets}}</b></p>
<h2>Assets</h2>
<table><tr><th>Type</th><th>Value</th><th>Scope</th><th>Priority</th><th>Ports</th><th>Technologies</th></tr>
{% for a in assets %}
<tr><td>{{a.asset_type}}</td><td>{{a.value}}</td>
<td class="{{a.scope_status|lower}}">{{a.scope_status}}</td>
<td>{{a.priority_score}}</td>
<td>{% for s in a.services %}<span class="badge">{{s.port}}/{{s.protocol}}</span>{% endfor %}</td>
<td>{% for t in a.technologies %}<span class="badge">{{t.name}}</span>{% endfor %}</td></tr>
{% endfor %}
</table></body></html>"""


def export_html(session: Session, project_id: uuid.UUID) -> bytes:
    from jinja2 import Template

    data = _collect(session, project_id)
    return Template(_HTML_TEMPLATE).render(
        name=data["project"]["name"],
        targets=", ".join(data["targets"]),
        assets=data["assets"],
    ).encode()
