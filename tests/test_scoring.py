from engine.scoring import AssetFacts, high_priority_threshold, score_asset
from plugins.technology.heuristic import _extract_version


def facts(**kw) -> AssetFacts:
    base = dict(value="x.example.com")
    base.update(kw)
    return AssetFacts(**base)


def test_plain_asset_scores_zero():
    score, reasons = score_asset(facts())
    assert score == 0
    assert reasons == []


def test_each_signal_adds_reasons():
    score, reasons = score_asset(
        facts(resolves_public_ip=True, live_http=True, newly_discovered=True))
    kinds = {r["reason"] for r in reasons}
    assert {"resolves_to_public_ip", "live_http_service", "newly_discovered"} <= kinds
    assert score > 0


def test_uncommon_ports_reported_with_ports_listed():
    score, reasons = score_asset(facts(open_ports=[8080, 8443]))
    reason = next(r for r in reasons if r["reason"] == "unusual_port_open")
    assert sorted(reason["ports"]) == [8080, 8443]
    assert score >= 20


def test_common_ports_do_not_trigger_uncommon_reason():
    _, reasons = score_asset(facts(open_ports=[80, 443]))
    assert all(r["reason"] != "unusual_port_open" for r in reasons)


def test_dev_indicator_is_strongest_single_signal():
    score_dev, _ = score_asset(facts(dev_indicator="dev"))
    score_http, _ = score_asset(facts(live_http=True))
    assert score_dev > score_http


def test_score_capped_at_100():
    score, _ = score_asset(facts(
        resolves_public_ip=True, open_ports=[1337], dev_indicator="dev",
        live_http=True, technologies=3, relationship_count=5,
        newly_discovered=True))
    assert score == 100


def test_low_confidence_penalty_can_reduce_score():
    with_penalty, _ = score_asset(facts(live_http=True, low_confidence_only=True))
    without_penalty, _ = score_asset(facts(live_http=True))
    assert with_penalty < without_penalty


def test_score_never_negative():
    score, _ = score_asset(facts(low_confidence_only=True))
    assert score == 0


def test_threshold_sanity():
    assert 0 < high_priority_threshold() <= 100


def test_version_extraction():
    assert _extract_version("nginx/1.24.0") == "1.24.0"
    assert _extract_version("Apache") is None
