"""Background job worker backed by the SQLite scans table.

A simpler alternative to Redis/Celery that fits a single-node MVP: jobs are
rows in ``scans`` with status ``queued``; workers claim them with an atomic
conditional UPDATE, so several worker threads/processes can share one DB.
Run standalone with ``python -m dfa.worker`` or in-process (default) inside
the API server.
"""
from __future__ import annotations

import logging
import os
import socket
import threading
import time
import traceback
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update

from .config import Settings, get_settings
from .db import session_scope
from .models import Scan, ScanEvent
from .pipeline import log_event, process_scan

log = logging.getLogger("dfa.worker")
STALE_AFTER = timedelta(minutes=30)


def claim_next(worker_id: str) -> str | None:
    with session_scope() as s:
        cand = s.execute(select(Scan.id).where(Scan.status == "queued").order_by(Scan.created_at).limit(1)).scalar()
        if not cand:
            return None
        res = s.execute(update(Scan).where(Scan.id == cand, Scan.status == "queued").values(
            status="running", worker_id=worker_id, started_at=datetime.now(UTC),
            heartbeat_at=datetime.now(UTC), attempts=Scan.attempts + 1, stage="starting", progress=1))
        return cand if res.rowcount == 1 else None


def recover_stale(settings: Settings) -> int:
    """Requeue (or fail) scans left 'running' by a crashed/restarted worker."""
    cutoff = datetime.now(UTC) - STALE_AFTER
    n = 0
    with session_scope() as s:
        for scan in s.execute(select(Scan).where(Scan.status == "running")).scalars():
            hb = scan.heartbeat_at
            if hb is not None and hb.tzinfo is None:
                hb = hb.replace(tzinfo=UTC)
            if hb is None or hb < cutoff or _owner_dead(scan.worker_id):
                n += 1
                if scan.attempts >= settings.max_attempts:
                    scan.status, scan.error = "failed", "worker interrupted repeatedly; giving up"
                    scan.finished_at = datetime.now(UTC)
                else:
                    scan.status, scan.stage = "queued", "requeued"
                s.add(ScanEvent(scan_id=scan.id, stage="worker", level="warning",
                                message=f"Recovered stale scan (status now {scan.status})"))
    return n


def _owner_dead(worker_id: str | None) -> bool:
    """True if the scan was claimed by a worker process on this host that no longer exists."""
    if not worker_id:
        return True
    parts = worker_id.split(":")
    if len(parts) < 2 or parts[0] != socket.gethostname() or not parts[1].isdigit():
        return False
    pid = int(parts[1])
    if pid == os.getpid():
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def _worker_prefix() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"


def run_one(scan_id: str, settings: Settings) -> None:
    try:
        process_scan(scan_id, settings)
        with session_scope() as s:
            scan = s.get(Scan, scan_id)
            scan.status, scan.stage, scan.progress = "completed", "complete", 100
            scan.finished_at = datetime.now(UTC)
    except Exception as exc:  # noqa: BLE001
        log.exception("scan %s failed", scan_id)
        log_event(scan_id, "failed", f"Scan failed: {type(exc).__name__}: {exc}", level="error")
        with session_scope() as s:
            scan = s.get(Scan, scan_id)
            scan.status, scan.stage = "failed", "failed"
            scan.error = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-2000:]}"
            scan.finished_at = datetime.now(UTC)


class Worker:
    def __init__(self, settings: Settings, threads: int = 1) -> None:
        self.settings = settings
        self.threads = threads
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        recover_stale(self.settings)
        for i in range(self.threads):
            t = threading.Thread(target=self._loop, args=(f"{_worker_prefix()}:{i}",), daemon=True,
                                 name=f"dfa-worker-{i}")
            t.start()
            self._threads.append(t)

    def notify(self) -> None:
        self._wake.set()

    def stop(self, timeout: float = 5) -> None:
        self._stop.set()
        self._wake.set()
        for t in self._threads:
            t.join(timeout)

    def _loop(self, wid: str) -> None:
        while not self._stop.is_set():
            try:
                sid = claim_next(wid)
            except Exception:  # noqa: BLE001
                log.exception("claim failed")
                sid = None
            if sid:
                run_one(sid, self.settings)
                continue
            self._wake.wait(self.settings.worker_poll_s)
            self._wake.clear()


def main() -> None:  # pragma: no cover - CLI
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = get_settings()
    w = Worker(settings, settings.worker_threads)
    w.start()
    log.info("worker started (%d thread(s))", settings.worker_threads)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        w.stop()


if __name__ == "__main__":  # pragma: no cover
    main()
