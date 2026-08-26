"""Attack-surface graph and shared-infrastructure endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Query

from backend.api.deps import SessionDep, get_project_or_404
from backend.models.entities import Asset, AssetType, Relationship
from backend.schemas.api import GraphEdge, GraphNode, GraphOut

router = APIRouter(prefix="/projects/{project_id}", tags=["graph"])


@router.get("/graph", response_model=GraphOut)
def get_graph(project_id: uuid.UUID, session: SessionDep,
              max_nodes: int = Query(500, ge=10, le=2000)) -> GraphOut:
    """Builds the graph from normalized data + relationships at request time."""
    get_project_or_404(session, project_id)
    assets = session.query(Asset).filter(Asset.project_id == project_id).all()
    rels = session.query(Relationship).filter(Relationship.project_id == project_id).all()

    nodes: dict[str, GraphNode] = {}
    edges: list[GraphEdge] = []

    def node_for_asset(asset: Asset) -> GraphNode:
        key = f"asset:{asset.id}"
        if key not in nodes:
            nodes[key] = GraphNode(id=key, label=asset.value,
                                   node_type=asset.asset_type.value,
                                   scope_status=asset.scope_status.value,
                                   score=asset.priority_score)
        return nodes[key]

    # Every discovered asset is a graph node; services & technologies expand
    # into derived nodes.
    for asset in assets:
        host_node = node_for_asset(asset)
        if asset.asset_type == AssetType.IP or asset.services:
            host_node = node_for_asset(asset)
            for svc in asset.services[:50]:  # safety cap per asset
                svc_id = f"service:{asset.id}:{svc.protocol}:{svc.port}"
                label = f"{svc.port}/{svc.protocol}" + (f" {svc.service_name}" if svc.service_name else "")
                nodes[svc_id] = GraphNode(id=svc_id, label=label, node_type="port",
                                          score=0)
                edges.append(GraphEdge(src=host_node.id, dst=svc_id, rel_type="EXPOSES"))
        if asset.technologies:
            host_node = node_for_asset(asset)
            for tech in asset.technologies[:25]:
                tech_id = f"technology:{tech.name.lower()}"
                if tech_id not in nodes:
                    nodes[tech_id] = GraphNode(id=tech_id, label=tech.name, node_type="technology")
                edges.append(GraphEdge(src=host_node.id, dst=tech_id, rel_type="RUNS"))

    for rel in rels:
        src_node = next((n for n in nodes.values()
                         if n.id == f"asset:{rel.src_asset_id}"), None)
        dst_key = f"asset:{rel.dst_asset_id}" if rel.dst_asset_id else f"value:{rel.dst_value}"
        if src_node is None:
            continue
        if dst_key not in nodes:
            nodes[dst_key] = GraphNode(id=dst_key, label=rel.dst_value,
                                       node_type="external", scope_status="UNKNOWN")
        edges.append(GraphEdge(src=src_node.id, dst=dst_key, rel_type=rel.rel_type))

    if len(nodes) > max_nodes:
        keep = {n.id for n in sorted(nodes.values(),
                                     key=lambda n: -n.score)[:max_nodes]}
        nodes = {k: v for k, v in nodes.items() if k in keep}
        edges = [e for e in edges if e.src in keep and e.dst in keep]

    return GraphOut(nodes=list(nodes.values()), edges=edges)


@router.get("/infrastructure/shared")
def shared_infrastructure(project_id: uuid.UUID, session: SessionDep) -> dict:
    from engine.correlation import shared_infrastructure as compute_shared

    get_project_or_404(session, project_id)
    return {"shared_ips": compute_shared(session, project_id)}
