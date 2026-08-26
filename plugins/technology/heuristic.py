"""Technology detection from stored HTTP evidence (heuristic adapter).

Deliberately conservative: every match carries a confidence value derived from
the strength of evidence. Server banners alone yield low confidence because
they are trivially spoofable. A Wappalyzer/fingerprint adapter can be added
later behind the same interface.
"""

from __future__ import annotations

import re

from engine.context import ScanContext
from plugins.base import AdapterResult, ReconAdapter

BODY_SIGNATURES: list[tuple[str, str, float]] = [
    (r"wp-content|wordpress", "WordPress", 0.8),
    (r"__NEXT_DATA__|/_next/static", "Next.js", 0.9),
    (r"/static/js/main\.|react(-dom)?(\.production)?\.min\.js", "React", 0.7),
    (r"ng-version=|angular\.min\.js", "Angular", 0.7),
    (r"vue(\.min)?\.js|data-v-app", "Vue.js", 0.7),
    (r"drupal\.js|drupal-settings-json", "Drupal", 0.8),
    (r"Joomla!", "Joomla", 0.9),
    (r"_ghost-url|content_api_key", "Ghost", 0.7),
    (r"laravel_session|XSRF-TOKEN.*laravel", "Laravel", 0.6),
    (r"django-admin|csrfmiddlewaretoken", "Django", 0.7),
    (r"jquery(-|\.)[0-9]", "jQuery", 0.6),
    (r"bootstrap(\.min)?\.(css|js)", "Bootstrap", 0.5),
]

HEADER_RULES: dict[str, tuple[str, float]] = {
    "x-powered-by": ("header:x-powered-by", 0.5),
    "x-generator": ("header:x-generator", 0.6),
}

SERVER_MAP = {
    "nginx": "nginx",
    "apache": "Apache httpd",
    "iis": "Microsoft IIS",
    "caddy": "Caddy",
    "litespeed": "LiteSpeed",
}


class HeuristicTechAdapter(ReconAdapter):
    stage = "technology"

    def name(self) -> str:
        return "tech-heuristic"

    def version(self) -> str:
        return "1.0"

    def check_installation(self) -> bool:
        return True

    async def run(self, ctx: ScanContext) -> AdapterResult:
        items = 0
        for result in ctx.http_results:
            url = result["url"]
            host = re.sub(r"^https?://", "", url).split("/")[0]
            headers = result.get("headers") or {}
            body_evidence = self.config.get("_bodies", {}).get(url)

            # Low confidence: banner only
            server = (result.get("server") or "").lower()
            for token, tech in SERVER_MAP.items():
                if token in server:
                    ctx.add_technology(host, tech,
                                       version=_extract_version(result.get("server")),
                                       confidence=0.4, source=self.name())
                    items += 1

            for header, (label, conf) in HEADER_RULES.items():
                val = headers.get(header)
                if val:
                    if header == "x-powered-by":
                        name = val.split("/")[0].strip().title()
                    else:
                        name = label.split(":")[1].title()
                    ctx.add_technology(host, name, version=_extract_version(val),
                                       confidence=conf, source=f"{self.name()}:{header}")
                    items += 1

            if body_evidence:
                for pattern, tech, conf in BODY_SIGNATURES:
                    if re.search(pattern, body_evidence, re.IGNORECASE):
                        ctx.add_technology(host, tech, version=None,
                                           confidence=conf, source=f"{self.name()}:body")
                        items += 1
        return AdapterResult(self.name(), self.stage, items=items)


def _extract_version(value: str | None) -> str | None:
    if not value:
        return None
    m = re.search(r"([0-9]+\.[0-9]+[0-9./]*)", value)
    return m.group(1) if m else None
