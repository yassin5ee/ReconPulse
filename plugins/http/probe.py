"""HTTP discovery adapter: probes hosts over http/https with httpx.

Collects status, title, redirect chain, selected headers, content length and
basic TLS metadata. Server banners are stored as *observations*, never as
authoritative truth (technology confidence is handled downstream).
"""

from __future__ import annotations

import asyncio
import ssl

import httpx

from engine.context import ScanContext
from plugins.base import AdapterResult, ReconAdapter


def _extract_title(body: str) -> str | None:
    lower = body[:20000].lower()
    start = lower.find("<title")
    if start == -1:
        return None
    open_end = body.find(">", start)
    close = body.find("</title", open_end)
    if open_end == -1 or close == -1:
        return None
    return body[open_end + 1:close].strip()[:300] or None


class HttpProbeAdapter(ReconAdapter):
    stage = "http"

    def name(self) -> str:
        return "http-probe"

    def version(self) -> str:
        return httpx.__version__

    def check_installation(self) -> bool:
        return True

    async def run(self, ctx: ScanContext) -> AdapterResult:
        hostnames = self.config.get("hostnames") or ctx.inputs.get("live_hostnames")
        if hostnames is None:
            hostnames = [h["value"] for h in ctx.hostnames]
        timeout = float(self.config.get("timeout", self.settings.http_probe_timeout))
        concurrency = int(self.config.get("concurrency", self.settings.max_concurrent_requests))
        follow_redirects = bool(self.config.get("follow_redirects", True))
        sem = asyncio.Semaphore(concurrency)
        found = 0

        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=follow_redirects,
            verify=self.config.get("verify_tls", True),
            headers={"User-Agent": self.config.get("user_agent", "ReconPulse/0.1 (+authorized-scan)")},
        ) as client:

            async def probe(host: str) -> int:
                count = 0
                for scheme in ("https", "http"):
                    url = f"{scheme}://{host}/"
                    try:
                        async with sem:
                            resp = await client.get(url)
                    except httpx.HTTPError:
                        continue
                    tls: dict = {}
                    if scheme == "https" and resp.extensions.get("ssl_object"):
                        ssl_obj: ssl.SSLObject = resp.extensions["ssl_object"]
                        cert = ssl_obj.getpeercert() or {}
                        tls = {
                            "subject_cn": next(
                                (v for rdn in cert.get("subject", ()) for k, v in rdn if k == "commonName"),
                                None,
                            ),
                            "not_after": dict(cert.get("notAfter", {})) or cert.get("notAfter"),
                        }
                    server = resp.headers.get("server")
                    ctx.add_http_result(
                        url=url,
                        status_code=resp.status_code,
                        title=_extract_title(resp.text),
                        headers={k.lower(): v for k, v in resp.headers.items()
                                 if k.lower() in (
                                     "server", "content-type", "location", "x-powered-by",
                                     "x-generator", "via", "strict-transport-security",
                                 )},
                        content_length=len(resp.content),
                        final_url=str(resp.url),
                        tls=tls,
                        server=server,
                        source=self.name(),
                    )
                    if resp.status_code > 0:
                        ctx.add_url(str(resp.url), source=self.name(),
                                    status=resp.status_code, title=_extract_title(resp.text))
                    count += 1
                    break  # one live scheme per host is enough for discovery
                return count

            results = await asyncio.gather(*(probe(h) for h in set(hostnames)))

        found = sum(results)
        return AdapterResult(self.name(), self.stage, items=found)
