"""Certificate Transparency subdomain adapter (crt.sh).

Passive reconnaissance only: queries the public CT log index. Requires no
external binary, making it the default MVP provider. Additional providers
(amass, subfinder, ...) can be dropped in as further adapters of this stage.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from engine.context import ScanContext
from plugins.base import AdapterResult, ReconAdapter

CRTSH_URL = "https://crt.sh/?output=json"


class CrtShAdapter(ReconAdapter):
    stage = "subdomain"

    def name(self) -> str:
        return "crtsh"

    def version(self) -> str:
        return "1.0"

    def check_installation(self) -> bool:
        return True

    async def run(self, ctx: ScanContext) -> AdapterResult:
        domains = self.config.get("domains") or ctx.inputs.get("domains") or []
        timeout = float(self.config.get("timeout", self.settings.http_probe_timeout * 3))
        found = 0
        errors: list[str] = []
        for domain in domains:
            try:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    resp = await client.get(CRTSH_URL, params={"q": f"%.{domain}"})
                resp.raise_for_status()
                for entry in self.parse_output(resp.text):
                    name = self._extract_name(entry)
                    if name and name.endswith("." + domain) or name == domain:
                        ctx.add_hostname(name, source=self.name())
                        found += 1
            except Exception as exc:  # noqa: BLE001 - reported per-domain
                errors.append(f"{domain}: {exc}")
        if errors and not found:
            return AdapterResult(self.name(), self.stage, success=False,
                                 error="; ".join(errors[:3]))
        return AdapterResult(self.name(), self.stage, items=found,
                             raw_summary={"errors": errors})

    @staticmethod
    def parse_output(body: str) -> list[dict[str, Any]]:
        """Safe parsing: tolerate non-JSON responses and size issues."""
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            # crt.sh sometimes returns HTML error pages under load.
            return []
        return data if isinstance(data, list) else []

    @staticmethod
    def _extract_name(entry: dict[str, Any]) -> str | None:
        raw = entry.get("name_value") or ""
        # name_value may contain newline-separated SANs.
        candidates = [n.strip().lower().lstrip("*.").rstrip(".") for n in str(raw).splitlines()]
        for candidate in candidates:
            if candidate and "*" not in candidate and " " not in candidate:
                return candidate
        return None
