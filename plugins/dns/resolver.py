"""DNS resolution adapter (A/AAAA/CNAME/MX/NS/TXT) using dnspython."""

from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.exception
import dns.resolver

from engine.context import ScanContext
from plugins.base import AdapterResult, ReconAdapter

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")


class DnsAdapter(ReconAdapter):
    stage = "dns"

    def name(self) -> str:
        return "dns-resolver"

    def version(self) -> str:
        return dns.__version__

    def check_installation(self) -> bool:
        return True

    async def run(self, ctx: ScanContext) -> AdapterResult:
        hostnames = self.config.get("hostnames") or ctx.inputs.get("resolved_hostnames")
        if hostnames is None:
            hostnames = [h["value"] for h in ctx.hostnames]
        timeout = float(self.config.get("timeout", self.settings.dns_timeout))
        resolver = dns.resolver.Resolver(configure=True)
        resolver.lifetime = timeout

        sem = asyncio.Semaphore(10)

        async def resolve(host: str) -> int:
            count = 0
            for rtype in RECORD_TYPES:
                try:
                    async with sem:
                        answers = await resolver.resolve(host, rtype)
                except (
                    dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.exception.Timeout,
                    OSError,
                ):
                    continue
                for rdata in answers:
                    value = str(getattr(rdata, "target", rdata)).rstrip(".")
                    ttl = getattr(answers, "ttl", None)
                    ctx.add_dns_record(host, rtype, value, ttl=ttl, source=self.name())
                    if rtype in ("A", "AAAA"):
                        ctx.add_ip(value, source=self.name(), hostname=host)
                    elif rtype == "CNAME":
                        ctx.add_hostname(value, source=f"{self.name()}:cname")
                    count += 1
            return count

        results = await asyncio.gather(*(resolve(h) for h in set(hostnames)))
        items = sum(results)
        return AdapterResult(self.name(), self.stage, items=items)
