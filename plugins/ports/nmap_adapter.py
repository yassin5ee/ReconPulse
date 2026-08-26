"""Port/service discovery via nmap.

Security-sensitive subsystem:
- Commands are built as argument arrays; shell=True is never used.
- Only fixed flags and validated targets/ports are accepted.
- Hard process timeout + output size cap.
- Conservative default: top-100 TCP ports, timing T3, no version detection on
  the quick profile.
"""

from __future__ import annotations

import asyncio
import shutil
import xml.etree.ElementTree as ET

from backend.core.logging import log_event
from engine.context import ScanContext
from plugins.base import AdapterResult, ReconAdapter

PROFILES = {
    "quick": {"args": ["--top-ports", "100", "-T3"]},
    "standard": {"args": ["--top-ports", "1000", "-T3", "-sV"]},
    "full": {"args": ["-p-", "-T3", "-sV"]},
}


class NmapAdapter(ReconAdapter):
    stage = "ports"
    requires_binary = True

    def name(self) -> str:
        return "nmap"

    def version(self) -> str:
        return self._version or "unknown"

    _version: str = "unknown"

    def check_installation(self) -> bool:
        return shutil.which("nmap") is not None

    def build_command(self, targets: list[str], profile: str) -> list[str]:
        """Argument array only. Targets are scope-validated by the pipeline before this call."""
        opts = PROFILES.get(profile, PROFILES["standard"])["args"]
        extra = [str(a) for a in self.config.get("extra_args", [])]
        return ["nmap", *opts, *extra, "-oX", "-", "--", *targets]

    async def execute(self, cmd: list[str]) -> tuple[int, bytes]:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={"PATH": self.config.get(
                "env_path", "/usr/local/bin:/usr/bin:/bin:/usr/sbin"
            )},  # controlled environment
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=float(self.settings.tool_timeout)
            )
        except TimeoutError:
            proc.kill()
            raise TimeoutError(
                f"{self.name()} exceeded {self.settings.tool_timeout}s") from None
        cap = int(self.settings.max_output_bytes)
        if len(stdout) > cap:
            raise ValueError("tool output exceeded size limit")
        if proc.returncode not in (0, None):
            raise RuntimeError(stderr.decode(errors="replace")[:500]) from None
        return proc.returncode or 0, stdout

    def parse_output(self, xml_bytes: bytes) -> list[dict]:
        results: list[dict] = []
        try:
            root = ET.fromstring(xml_bytes)
        except ET.ParseError as exc:
            raise ValueError(f"invalid nmap XML: {exc}") from exc
        for host in root.iter("host"):
            addr_el = host.find("address")
            if addr_el is None:
                continue
            ip = addr_el.get("addr") or ""
            for port in host.iter("port"):
                state_el = port.find("state")
                svc_el = port.find("service")
                if state_el is None or state_el.get("state") != "open":
                    continue
                version = ""
                if svc_el is not None:
                    product = svc_el.get("product") or ""
                    ver = svc_el.get("version")
                    version = f"{product} {ver}".strip() if ver else product
                results.append({
                    "ip": ip,
                    "port": int(port.get("portid", "0")),
                    "protocol": port.get("protocol", "tcp"),
                    "service_name": (svc_el.get("name") if svc_el is not None else "") or "",
                    "version": version or None,
                    "state": "open",
                })
        return results

    @staticmethod
    def _blocked(ctx: ScanContext, rec: dict) -> bool:
        from backend.models.entities import ScopeStatus

        if not ctx.scope.allows_active_scan(rec["value"]):
            return True
        return any(ctx.scope.classify(h) == ScopeStatus.OUT_OF_SCOPE
                   for h in rec["hostnames"])

    async def run(self, ctx: ScanContext) -> AdapterResult:
        # Scope gate: an IP is actively scanned only when the IP itself is
        # IN_SCOPE and none of its associated hostnames is explicitly DENY'd.
        targets = [rec["value"] for rec in ctx.ips if not self._blocked(ctx, rec)]
        skipped_out_of_scope = len(ctx.ips) - len(targets)
        if not targets:
            return AdapterResult(self.name(), self.stage, success=True, items=0,
                                 raw_summary={"skipped_out_of_scope": skipped_out_of_scope})
        log_event(ctx.logger, "info", "active_scan_targets", scan_id=str(ctx.scan_id),
                  adapter=self.name(), count=len(targets))

        profile = self.config.get("profile", ctx.inputs.get("scan_profile", "standard"))
        cmd = self.build_command(targets, profile)
        _, stdout = await self.execute(cmd)
        services = self.parse_output(stdout)
        ip_to_host = {rec["value"]: rec["hostnames"][0]
                      for rec in ctx.ips if rec["hostnames"]}
        for svc in services:
            host = ip_to_host.get(svc["ip"], svc["ip"])
            ctx.add_service(host=svc["ip"], port=svc["port"], protocol=svc["protocol"],
                            service_name=svc["service_name"], version=svc["version"],
                            source=self.name())
            # web ports imply URL candidates even when HTTP probing missed them
            if svc["port"] == 443:
                ctx.add_url(f"https://{host}/", source=f"{self.name()}:port")
            elif svc["port"] == 80:
                ctx.add_url(f"http://{host}/", source=f"{self.name()}:port")
        return AdapterResult(self.name(), self.stage, items=len(services),
                             raw_summary={"targets": len(targets),
                                          "skipped_out_of_scope": skipped_out_of_scope})
