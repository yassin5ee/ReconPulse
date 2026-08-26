"""ScanContext: in-flight buffer of normalized reconnaissance items.

Adapters push normalized items here; the pipeline persists them with dedup,
scope classification and source attribution. Nothing in the context is trusted
raw tool output.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from backend.core.logging import log_event
from engine.normalization import normalize_hostname, normalize_ip, normalize_url
from engine.scope import ScopeChecker


@dataclass
class ScanContext:
    project_id: uuid.UUID
    scan_id: uuid.UUID
    scope: ScopeChecker
    logger: logging.Logger = field(default_factory=logging.getLogger)
    inputs: dict[str, Any] = field(default_factory=dict)  # cross-stage data flow

    hostnames: list[dict] = field(default_factory=list)
    ips: list[dict] = field(default_factory=list)
    urls: list[dict] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    dns_records: list[dict] = field(default_factory=list)
    http_results: list[dict] = field(default_factory=list)
    technologies: list[dict] = field(default_factory=list)

    # ------------------------------------------------------------------ emitters

    def add_hostname(self, hostname: str, source: str, status: str = "discovered") -> None:
        host = normalize_hostname(hostname)
        if not host or any(h["value"] == host for h in self.hostnames):
            return
        log_event(self.logger, "info", "asset_discovered", scan_id=str(self.scan_id),
                  type="hostname", value=host, source=source)
        self.hostnames.append({"value": host, "source": source, "status": status})

    def add_ip(self, ip: str, source: str, hostname: str | None = None) -> None:
        addr = normalize_ip(ip)
        if not addr:
            return
        for rec in self.ips:
            if rec["value"] == addr:
                if hostname and hostname not in rec["hostnames"]:
                    rec["hostnames"].append(hostname)
                return
        self.ips.append({"value": addr, "source": source, "hostnames": [hostname] if hostname else []})

    def add_url(self, url: str, source: str, **meta: Any) -> None:
        norm = normalize_url(url)
        if not norm or any(u["value"] == norm for u in self.urls):
            return
        log_event(self.logger, "info", "asset_discovered", scan_id=str(self.scan_id),
                  type="url", value=norm, source=source)
        self.urls.append({"value": norm, "source": source, "meta": meta})

    def add_service(self, host: str, port: int, protocol: str = "tcp",
                    service_name: str = "", version: str | None = None,
                    state: str = "open", source: str = "") -> None:
        self.services.append({
            "host": host, "port": int(port), "protocol": protocol,
            "service_name": service_name, "version": version, "state": state, "source": source,
        })

    def add_dns_record(self, hostname: str, record_type: str, value: str,
                       ttl: int | None = None, source: str = "") -> None:
        self.dns_records.append({
            "hostname": normalize_hostname(hostname) or hostname,
            "record_type": record_type.upper(), "value": value.strip(),
            "ttl": ttl, "source": source,
        })

    def add_http_result(self, url: str, status_code: int | None, title: str | None,
                        headers: dict[str, str], content_length: int | None,
                        final_url: str | None, tls: dict[str, Any] | None,
                        server: str | None, source: str) -> None:
        self.http_results.append({
            "url": url, "status_code": status_code, "title": title, "headers": headers,
            "content_length": content_length, "final_url": final_url,
            "tls": tls or {}, "server": server, "source": source,
        })

    def add_technology(self, asset_value: str, name: str, version: str | None,
                       confidence: float, source: str) -> None:
        self.technologies.append({
            "host": asset_value, "name": name, "version": version,
            "confidence": float(max(0.0, min(1.0, confidence))), "source": source,
        })
