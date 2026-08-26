"""Scope management.

Scope is a hard security boundary: assets classified OUT_OF_SCOPE are never
actively scanned by the pipeline. Classification:

- DENY rules are evaluated first (an explicit deny always wins).
- ALLOW rules match exact hosts, wildcard domains (*.example.com covers the
  apex and any-depth subdomains), and CIDR ranges for IPs.
- Anything unmatched is UNKNOWN; the pipeline treats UNKNOWN as out of scope
  for *active* stages.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from backend.models.entities import RuleType, ScopeStatus


def normalize_host(value: str) -> str:
    return value.strip().lower().rstrip(".")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(normalize_host(value))
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class ScopePattern:
    raw: str
    rule_type: RuleType

    def __post_init__(self) -> None:
        object.__setattr__(self, "raw", normalize_host(self.raw))


def _domain_matches(host: str, pattern_raw: str) -> bool:
    """Wildcard-aware domain matching.

    example.com        -> matches only example.com
    *.example.com      -> matches example.com and any subdomain at any depth
    """
    if host == pattern_raw:
        return True
    if pattern_raw.startswith("*."):
        base = pattern_raw[2:]
        return host == base or host.endswith("." + base)
    return False


def _ip_matches(ip: str, pattern_raw: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if "/" in pattern_raw:
        try:
            return addr in ipaddress.ip_network(pattern_raw, strict=False)
        except ValueError:
            return False
    try:
        return addr == ipaddress.ip_address(pattern_raw)
    except ValueError:
        return False


class ScopeChecker:
    def __init__(self, rules: list[tuple[str, str]]):
        """rules: list of (pattern, rule_type) where rule_type in {"ALLOW", "DENY"}."""
        self._patterns = [ScopePattern(p, RuleType(t)) for p, t in rules]

    @property
    def has_allow_rules(self) -> bool:
        return any(p.rule_type == RuleType.ALLOW for p in self._patterns)

    def classify(self, value: str) -> ScopeStatus:
        value = normalize_host(value)
        if not value:
            return ScopeStatus.UNKNOWN

        deny = any(
            self._match(p.raw, value) for p in self._patterns if p.rule_type == RuleType.DENY
        )
        if deny:
            return ScopeStatus.OUT_OF_SCOPE

        allow = any(
            self._match(p.raw, value) for p in self._patterns if p.rule_type == RuleType.ALLOW
        )
        if allow:
            return ScopeStatus.IN_SCOPE
        return ScopeStatus.UNKNOWN

    def allows_active_scan(self, value: str) -> bool:
        """Only IN_SCOPE assets may be actively probed."""
        return self.classify(value) == ScopeStatus.IN_SCOPE

    @staticmethod
    def _match(pattern: str, value: str) -> bool:
        if is_ip(value):
            return _ip_matches(value, pattern)
        return _domain_matches(value, pattern)


def checker_from_project(scope_rules) -> ScopeChecker:
    return ScopeChecker([(r.pattern, r.rule_type.value) for r in scope_rules])
