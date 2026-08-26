"""Normalization of raw reconnaissance values into canonical form."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\Z)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*"
    r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\Z",
    re.IGNORECASE,
)

# Hostname tokens that commonly indicate non-production systems.
DEV_INDICATORS = ("dev", "stage", "staging", "test", "uat", "qa", "sandbox", "beta", "demo", "internal")


def normalize_hostname(value: str) -> str | None:
    """Lowercase, strip trailing dot and scheme/port; return None when invalid."""
    if not value:
        return None
    host = value.strip().lower().rstrip(".")
    if "://" in host:
        host = urlsplit(host).hostname or ""
    host = host.split("/")[0].split(":")[0]
    host = host.rstrip(".")
    if not host or len(host) > 253:
        return None
    if not HOSTNAME_RE.match(host):
        return None
    return host


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def normalize_ip(value: str) -> str | None:
    candidate = value.strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def normalize_url(value: str) -> str | None:
    """Canonical URL: lowercase scheme/host, no default port, no fragment."""
    if not value:
        return None
    value = value.strip()
    if "://" not in value:
        value = "http://" + value
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if not parts.scheme or parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    netloc = parts.hostname.lower()
    default = (parts.scheme == "http" and parts.port == 80) or (
        parts.scheme == "https" and parts.port == 443
    )
    if parts.port and not default:
        netloc = f"{netloc}:{parts.port}"
    path = parts.path or "/"
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme}://{netloc}{path}{query}"


def parent_domain(hostname: str) -> str | None:
    parts = hostname.split(".")
    if len(parts) < 3:
        return ".".join(parts[-2:]) if len(parts) == 2 else None
    return ".".join(parts[-2:])


def has_dev_indicator(hostname: str) -> str | None:
    labels = set(re.split(r"[.\-_]", hostname.lower()))
    for indicator in DEV_INDICATORS:
        if indicator in labels:
            return indicator
    return None


def dedupe(items: list[dict], key_field: str) -> list[dict]:
    """Keep first occurrence per key_field, merging `sources` lists."""
    seen: dict[str, dict] = {}
    for item in items:
        key = item.get(key_field)
        if key is None:
            continue
        if key in seen:
            src = item.get("source")
            existing = seen[key].setdefault("sources", [seen[key].get("source")])
            if src and src not in existing:
                existing.append(src)
        else:
            seen[key] = dict(item)
            seen[key]["sources"] = [item.get("source")] if item.get("source") else []
    return list(seen.values())
