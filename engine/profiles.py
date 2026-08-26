"""Scan profiles define which pipeline stages run and with which defaults.

Active modules always require explicit configuration; defaults are conservative.
"""

from __future__ import annotations

from typing import Any

STAGE_ORDER: list[str] = ["subdomain", "dns", "http", "ports", "technology"]

PROFILES: dict[str, dict[str, Any]] = {
    "quick": {"stages": ["subdomain", "dns", "http"]},
    "standard": {"stages": ["subdomain", "dns", "http", "ports", "technology"]},
    "full": {"stages": ["subdomain", "dns", "http", "ports", "technology"]},
}

# Conservative nmap profile mapping (full port range is opt-in via config only).
NMAP_PROFILE_BY_SCAN_PROFILE = {"quick": "quick", "standard": "standard", "full": "standard"}


def resolve_profile(profile: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
    config = config or {}
    if profile == "custom":
        stages_list = [s for s in STAGE_ORDER if config.get("stages", {}).get(s)]
    else:
        base = PROFILES.get(profile, PROFILES["standard"])
        overrides = config.get("stages", {})
        stages_list = [s for s in base["stages"]
                       if overrides.get(s, True)]
    return {
        "stages": [s for s in STAGE_ORDER if s in stages_list],
        "ports_profile": NMAP_PROFILE_BY_SCAN_PROFILE.get(profile, "standard"),
    }
