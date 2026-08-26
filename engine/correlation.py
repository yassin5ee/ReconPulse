"""Attack-surface correlation.

Builds relationships between normalized entities (never raw tool outputs):

  subdomain --SUBDOMAIN_OF--> domain
  hostname  --RESOLVES_TO---> ip
  hostname  --CNAME_TO------> target
  asset     --HOSTS_URL-----> url
  asset     --RUNS----------> technology (expanded at graph time)

Shared-infrastructure detection: multiple hostnames resolving to the same IP
are surfaced by the hub_asset scoring signal and visible in the graph.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models.entities import Asset, AssetType, Relationship


def build_relationships(session: Session, project_id: uuid.UUID, scan_id: uuid.UUID | None) -> int:
    """Rebuild the current-surface relationship set for a project. Returns edge count."""
    assets = session.scalars(
        select(Asset).where(Asset.project_id == project_id)
    ).all()

    by_value: dict[tuple[str, str], Asset] = {(a.asset_type.value, a.value): a for a in assets}
    edges: list[dict[str, Any]] = []
    seen: set[tuple[uuid.UUID, str, str]] = set()

    def add(src: Asset, dst_value: str, rel: str,
            dst: Asset | None = None) -> None:
        key = (src.id, rel, dst.id if dst else dst_value)
        if src.id == (dst.id if dst else None) or (dst is None and src.value == dst_value):
            return
        if key in seen:
            return
        seen.add(key)
        edges.append({
            "project_id": project_id, "src_asset_id": src.id,
            "dst_asset_id": dst.id if dst else None,
            "dst_value": dst.value if dst else dst_value,
            "rel_type": rel, "scan_id": scan_id,
        })

    for asset in assets:
        host = asset.value
        if asset.asset_type in (AssetType.DOMAIN, AssetType.SUBDOMAIN):
            # SUBDOMAIN_OF: link to the closest known parent domain/subdomain asset
            parts = host.split(".")
            for i in range(1, len(parts) - 1):
                parent = ".".join(parts[i:])
                dst = by_value.get(("domain", parent)) or by_value.get(("subdomain", parent))
                if dst and dst.id != asset.id:
                    add(asset, parent, "SUBDOMAIN_OF", dst)
                    break

        for rec in asset.dns_records:
            if rec.record_type == "A":
                dst = by_value.get(("ip", rec.value))
                add(asset, rec.value, "RESOLVES_TO", dst)
            elif rec.record_type == "AAAA":
                dst = by_value.get(("ip", rec.value))
                add(asset, rec.value, "RESOLVES_TO", dst)
            elif rec.record_type == "CNAME":
                dst = (by_value.get(("subdomain", rec.value))
                       or by_value.get(("domain", rec.value)))
                add(asset, rec.value, "CNAME_TO", dst)

    # HOSTS_URL: url -> its host asset (reverse direction stored on the host)
    for asset in assets:
        if asset.asset_type == AssetType.URL:
            host = asset.value.split("://")[1].split("/")[0]
            dst = (by_value.get(("subdomain", host)) or by_value.get(("domain", host))
                   or by_value.get(("ip", host)))
            if dst:
                add(dst, asset.value, "HOSTS_URL", asset)

    session.query(Relationship).filter(Relationship.project_id == project_id).delete()
    for edge in edges:
        session.add(Relationship(**edge))
    return len(edges)


def shared_infrastructure(session: Session, project_id: uuid.UUID) -> dict[str, list[str]]:
    """Map IP -> list of hostnames pointing at it (shared infra / virtual hosts)."""
    from backend.models.entities import DnsRecord  # local import avoids cycles

    mapping: dict[str, list[str]] = {}
    rows = (
        session.query(DnsRecord, Asset.value)
        .join(Asset, DnsRecord.asset_id == Asset.id)
        .filter(Asset.project_id == project_id, DnsRecord.record_type.in_(["A", "AAAA"]))
        .all()
    )
    for record, host in rows:
        mapping.setdefault(record.value, []).append(host)
    return {ip: hosts for ip, hosts in mapping.items() if len(hosts) > 1}
