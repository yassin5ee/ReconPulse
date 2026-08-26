"""ReconPulse worker: claims queued scans from PostgreSQL and runs the pipeline.

MVP design: single sequential consumer polling the scans table. The queue
semantics are intentionally trivial so they can later be replaced by Celery/RQ
without touching the pipeline itself (engine.pipeline.run_scan is the contract).
"""

from __future__ import annotations

import logging
import time
import uuid

from sqlalchemy import select, update

from backend.core.config import get_settings
from backend.core.logging import configure_logging, log_event
from backend.database.session import SessionLocal
from backend.models.entities import Scan, ScanStatus

logger = logging.getLogger("reconpulse.worker")


def claim_next_scan() -> uuid.UUID | None:
    """Atomically move the oldest queued scan to RUNNING."""
    with SessionLocal() as session:
        scan_id = session.scalar(
            select(Scan.id).where(Scan.status == ScanStatus.QUEUED)
            .order_by(Scan.id).limit(1)
        )
        if scan_id is not None:
            session.execute(
                update(Scan)
                .where(Scan.id == scan_id, Scan.status == ScanStatus.QUEUED)
                .values(status=ScanStatus.RUNNING)
            )
            session.commit()
            return scan_id
    return None


def run_claimed(scan_id: uuid.UUID) -> None:
    from engine import pipeline  # local import: heavy deps only when needed

    try:
        pipeline.run_scan(SessionLocal, scan_id)
    except Exception as exc:  # noqa: BLE001 - worker must survive any failure
        log_event(logger, "error", "worker_scan_crashed",
                  scan_id=str(scan_id), error=str(exc))
        with SessionLocal() as session:
            scan = session.get(Scan, scan_id)
            if scan is not None and scan.status == ScanStatus.RUNNING:
                scan.status = ScanStatus.FAILED
                scan.error = f"worker crash: {exc}"[:2000]
                session.commit()


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    log_event(logger, "info", "worker_started")
    while True:
        try:
            scan_id = claim_next_scan()
        except Exception as exc:  # noqa: BLE001 - e.g. schema not migrated yet
            log_event(logger, "warning", "worker_poll_failed", error=str(exc))
            time.sleep(settings.worker_poll_interval)
            continue
        if scan_id is None:
            time.sleep(settings.worker_poll_interval)
            continue
        log_event(logger, "info", "scan_claimed", scan_id=str(scan_id))
        run_claimed(scan_id)


if __name__ == "__main__":
    main()
