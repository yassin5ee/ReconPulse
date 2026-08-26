"""Transparent reconnaissance priority scoring.

This is NOT vulnerability severity. The score answers:
"which discovered assets deserve manual investigation first?"

Every point of the score is justified by explicit reasons stored on the asset,
so a human can audit why an item ranked highly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from engine.normalization import has_dev_indicator

WEIGHTS = {
    "resolves_public_ip": 15,
    "open_uncommon_port": 20,
    "dev_indicator": 25,
    "live_http": 10,
    "multiple_technologies": 10,
    "hub_asset": 15,
    "newly_discovered": 5,
    "low_confidence_only": -10,
}
MAX_SCORE = 100


@dataclass
class AssetFacts:
    value: str
    resolves_public_ip: bool = False
    open_ports: list[int] = field(default_factory=list)
    dev_indicator: str | None = None
    live_http: bool = False
    technologies: int = 0
    relationship_count: int = 0
    newly_discovered: bool = False
    low_confidence_only: bool = False


COMMON_PORTS = {80, 443}


def score_asset(facts: AssetFacts) -> tuple[int, list[dict[str, Any]]]:
    reasons: list[dict[str, Any]] = []
    score = 0

    if facts.resolves_public_ip:
        score += WEIGHTS["resolves_public_ip"]
        reasons.append({"reason": "resolves_to_public_ip", "points": WEIGHTS["resolves_public_ip"]})

    uncommon = [p for p in facts.open_ports if p not in COMMON_PORTS]
    if uncommon:
        score += WEIGHTS["open_uncommon_port"]
        reasons.append({"reason": "unusual_port_open", "ports": uncommon,
                        "points": WEIGHTS["open_uncommon_port"]})

    if facts.dev_indicator:
        score += WEIGHTS["dev_indicator"]
        reasons.append({"reason": "development_staging_indicator",
                        "indicator": facts.dev_indicator, "points": WEIGHTS["dev_indicator"]})

    if facts.live_http:
        score += WEIGHTS["live_http"]
        reasons.append({"reason": "live_http_service", "points": WEIGHTS["live_http"]})

    if facts.technologies >= 2:
        score += WEIGHTS["multiple_technologies"]
        reasons.append({"reason": "multiple_technologies_detected",
                        "count": facts.technologies, "points": WEIGHTS["multiple_technologies"]})

    if facts.relationship_count >= 3:
        score += WEIGHTS["hub_asset"]
        reasons.append({"reason": "shared_infrastructure_hub",
                        "relationships": facts.relationship_count, "points": WEIGHTS["hub_asset"]})

    if facts.newly_discovered:
        score += WEIGHTS["newly_discovered"]
        reasons.append({"reason": "newly_discovered", "points": WEIGHTS["newly_discovered"]})

    if facts.low_confidence_only:
        score += WEIGHTS["low_confidence_only"]
        reasons.append({"reason": "evidence_low_confidence", "points": WEIGHTS["low_confidence_only"]})

    return max(0, min(MAX_SCORE, score)), reasons


def high_priority_threshold() -> int:
    return 40


def dev_indicator_for(value: str) -> str | None:
    return has_dev_indicator(value)
