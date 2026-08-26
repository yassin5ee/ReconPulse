"""Plugin/adapter abstraction.

Every external reconnaissance capability implements ReconAdapter. Adapters for
external binaries additionally implement build_command()/execute()/parse_output()
(see plugins/base_tool.py); pure-network adapters (crt.sh, DNS, HTTP probing)
implement run() directly.

The engine only knows about ScanContext + normalized items; it never imports a
specific tool.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

from backend.core.config import get_settings
from backend.core.logging import log_event
from engine.context import ScanContext


@dataclass
class AdapterResult:
    adapter: str
    stage: str
    success: bool = True
    error: str | None = None
    items: int = 0
    raw_summary: dict[str, Any] = field(default_factory=dict)


class ReconAdapter(ABC):
    stage: ClassVar[str]
    #: when True the pipeline skips this adapter if check_installation() fails
    requires_binary: ClassVar[bool] = False

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config: dict[str, Any] = config or {}
        self.settings = get_settings()

    @abstractmethod
    def name(self) -> str: ...

    def version(self) -> str:
        return "unknown"

    @abstractmethod
    def check_installation(self) -> bool:
        """Return True when this adapter can run in the current environment."""

    @abstractmethod
    async def run(self, ctx: ScanContext) -> AdapterResult:
        """Execute the reconnaissance capability and emit normalized items into ctx."""


async def gather_adapters(
    ctx: ScanContext,
    adapters: list[ReconAdapter],
    concurrency: int = 4,
) -> list[AdapterResult]:
    """Run adapters with bounded concurrency; one failure never aborts the rest."""
    sem = asyncio.Semaphore(concurrency)

    async def _run(adapter: ReconAdapter) -> AdapterResult:
        async with sem:
            try:
                if not adapter.check_installation():
                    return AdapterResult(
                        adapter=adapter.name(), stage=adapter.stage, success=False,
                        error="not installed",
                    )
                result = await adapter.run(ctx)
                return result
            except Exception as exc:  # noqa: BLE001 - module isolation by design
                log_event(ctx.logger, "error", "adapter_failed",
                          scan_id=ctx.scan_id, adapter=adapter.name(), error=str(exc))
                return AdapterResult(
                    adapter=adapter.name(), stage=adapter.stage, success=False, error=str(exc),
                )

    return list(await asyncio.gather(*(_run(a) for a in adapters)))
