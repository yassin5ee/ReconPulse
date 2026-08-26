from sqlalchemy import select

from backend.models.entities import AssetType, Relationship
from engine.correlation import build_relationships, shared_infrastructure
from tests.conftest import make_asset, make_dns_record


def _edges(session_factory, pid):
    with session_factory() as s:
        rels = s.scalars(select(Relationship).where(Relationship.project_id == pid)).all()
        return {(r.src_asset_id, r.rel_type, r.dst_asset_id or r.dst_value) for r in rels}


def test_subdomain_of_relationship(session_factory, project_id):
    domain = make_asset(session_factory, project_id, "example.com",
                        asset_type=AssetType.DOMAIN)
    sub = make_asset(session_factory, project_id, "api.example.com")
    with session_factory() as s:
        build_relationships(s, project_id, None)
        s.commit()
    edges = _edges(session_factory, project_id)
    assert any(rel == "SUBDOMAIN_OF" and src == sub and dst == domain
               for src, rel, dst in edges)


def test_resolves_to_creates_ip_link(session_factory, project_id):
    sub = make_asset(session_factory, project_id, "api.example.com")
    ip = make_asset(session_factory, project_id, "1.2.3.4", asset_type=AssetType.IP)
    make_dns_record(session_factory, sub, "A", "1.2.3.4")
    with session_factory() as s:
        build_relationships(s, project_id, None)
        s.commit()
    edges = _edges(session_factory, project_id)
    assert any(src == sub and rel == "RESOLVES_TO" and dst == ip
               for src, rel, dst in edges)


def test_cname_to_relationship(session_factory, project_id):
    www = make_asset(session_factory, project_id, "www.example.com")
    target = make_asset(session_factory, project_id, "hosting.example.net")
    make_dns_record(session_factory, www, "CNAME", "hosting.example.net")
    with session_factory() as s:
        build_relationships(s, project_id, None)
        s.commit()
    edges = _edges(session_factory, project_id)
    assert any(src == www and rel == "CNAME_TO" and dst == target
               for src, rel, dst in edges)


def test_hosts_url_relationship(session_factory, project_id):
    sub = make_asset(session_factory, project_id, "api.example.com")
    url = make_asset(session_factory, project_id, "https://api.example.com/",
                     asset_type=AssetType.URL)
    with session_factory() as s:
        build_relationships(s, project_id, None)
        s.commit()
    edges = _edges(session_factory, project_id)
    assert any(src == sub and rel == "HOSTS_URL" and dst == url
               for src, rel, dst in edges)


def test_shared_infrastructure_detection(session_factory, project_id):
    a = make_asset(session_factory, project_id, "api.example.com")
    b = make_asset(session_factory, project_id, "dev.example.com")
    c = make_asset(session_factory, project_id, "lonely.example.com")
    make_dns_record(session_factory, a, "A", "1.2.3.4")
    make_dns_record(session_factory, b, "A", "1.2.3.4")
    make_dns_record(session_factory, c, "A", "9.9.9.9")
    with session_factory() as s:
        result = shared_infrastructure(s, project_id)
    assert set(result["1.2.3.4"]) == {"api.example.com", "dev.example.com"}
    assert "9.9.9.9" not in result


def test_rebuild_is_idempotent(session_factory, project_id):
    sub = make_asset(session_factory, project_id, "api.example.com")
    make_dns_record(session_factory, sub, "A", "1.2.3.4")
    with session_factory() as s:
        n1 = build_relationships(s, project_id, None)
        s.commit()
    with session_factory() as s:
        n2 = build_relationships(s, project_id, None)
        s.commit()
    assert n1 == n2 > 0


def test_self_edges_never_created(session_factory, project_id):
    make_asset(session_factory, project_id, "example.com", asset_type=AssetType.DOMAIN)
    with session_factory() as s:
        build_relationships(s, project_id, None)
        s.commit()
    edges = _edges(session_factory, project_id)
    assert all(src != dst for src, _, dst in edges)
