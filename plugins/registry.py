"""Adapter registry. Adding a new tool = subclass ReconAdapter + register here."""

from __future__ import annotations

from typing import Any

from plugins.base import ReconAdapter
from plugins.dns.resolver import DnsAdapter
from plugins.http.probe import HttpProbeAdapter
from plugins.ports.nmap_adapter import NmapAdapter
from plugins.subdomain.crtsh import CrtShAdapter
from plugins.technology.heuristic import HeuristicTechAdapter

_REGISTRY: dict[str, list[type[ReconAdapter]]] = {}


def register(adapter_cls: type[ReconAdapter]) -> type[ReconAdapter]:
    _REGISTRY.setdefault(adapter_cls.stage, []).append(adapter_cls)
    return adapter_cls


def get_adapters(stage: str, config: dict[str, Any] | None = None) -> list[ReconAdapter]:
    cfg = config or {}
    instances: list[ReconAdapter] = []
    for cls in _REGISTRY.get(stage, []):
        adapter_cfg = cfg.get(stage, {}).get(cls().name(), {})
        instances.append(cls(config=adapter_cfg))
    return instances


def stages() -> list[str]:
    return sorted(_REGISTRY)


for cls in (CrtShAdapter, DnsAdapter, HttpProbeAdapter, NmapAdapter, HeuristicTechAdapter):
    register(cls)
