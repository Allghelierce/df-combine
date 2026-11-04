"""FastAPI application."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from . import __version__
from .adapters.registry import all_statuses
from .config import Settings, get_settings
from .db import get_session, init_engine
from .models import FindingRow, Scan, ScanEvent
from .reports.export import finding_to_dict, json_report, pdf_report, scan_to_dict
from .sandbox import resolve_mode
from .worker import Worker

log = logging.getLogger("dfa.api")
CHUNK = 1024 * 1024


def create_app(settings: Settings | None = None, start_worker: bool | None = None) -> FastAPI:
    settings = settings or get_settings()
    settings.ensure_dirs()
    init_engine(settings.db_url)
    worker_holder: dict[str, Worker] = {}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        run_worker = settings.worker_mode == "inprocess" if start_worker is None else start_worker
        if run_worker:
            w = Worker(settings, settings.worker_threads)
            w.start()
            worker_holder["w"] = w
        yield
        if "w" in worker_holder:
            worker_holder["w"].stop()

    app = FastAPI(title="Drone Firmware Analyzer", version=__version__, lifespan=lifespan,
                  docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.state.settings = settings
    app.state.worker = worker_holder
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["*"],
                       allow_headers=["*"], expose_headers=["Content-Disposition"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        if settings.api_key and request.url.path.startswith("/api/") and request.url.path not in (
                "/api/health", "/api/docs", "/api/openapi.json") and request.method != "OPTIONS":
            supplied = request.headers.get("x-api-key") or request.query_params.get("api_key")
            if supplied != settings.api_key:
                return JSONResponse({"detail": "invalid or missing API key"}, status_code=401)
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        return resp

    # ------------------------------------------------------------------ meta
    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": __version__}

    @app.get("/api/config")
    def config():
        try:
            mode, detail = resolve_mode(settings)
        except Exception as exc:  # noqa: BLE001
            mode, detail = "unavailable", str(exc)
        return {"version": __version__, "max_upload_mb": settings.max_upload_mb, "sandbox_mode": mode,
                "sandbox_detail": detail, "worker_mode": settings.worker_mode,
                "limits": settings.limits_dict(), "auth_required": bool(settings.api_key)}

    @app.get("/api/tools")
    def tools():
        return {"tools": all_statuses(settings)}

    @app.get("/api/stats")
    def stats(db: Session = Depends(get_session)):
        by_status = dict(db.execute(select(Scan.status, func.count()).group_by(Scan.status)).all())
        by_sev = dict(db.execute(select(FindingRow.severity, func.count()).group_by(FindingRow.severity)).all())
        by_cls = dict(db.execute(select(FindingRow.classification, func.count())
                                 .group_by(FindingRow.classification)).all())
        platforms: dict[str, int] = {}
        for (ident,) in db.execute(select(Scan.identification).where(Scan.status == "completed")).all():
            p = (ident or {}).get("platform") or "Unknown"
            platforms[p] = platforms.get(p, 0) + 1
        return {"scans": by_status, "total_scans": sum(by_status.values()), "findings_by_severity": by_sev,
                "findings_by_classification": by_cls, "platforms": platforms}

    # ------------------------------------------------------------------ scans
    @app.post("/api/scans", status_code=201)
    async def upload(file: UploadFile, db: Session = Depends(get_session)):
        if not file.filename:
            raise HTTPException(400, "missing filename")
        scan_id = str(uuid.uuid4())
        dest = settings.uploads_dir / f"{scan_id}.bin"
        limit = settings.max_upload_mb * CHUNK
        h = hashlib.sha256()
        size = 0
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        try:
            with os.fdopen(fd, "wb") as out:
                while chunk := await file.read(CHUNK):
                    size += len(chunk)
                    if size > limit:
                        raise HTTPException(413, f"file exceeds upload limit of {settings.max_upload_mb} MiB")
                    h.update(chunk)
                    out.write(chunk)
        except BaseException:
            dest.unlink(missing_ok=True)
            raise
        if size == 0:
            dest.unlink(missing_ok=True)
            raise HTTPException(400, "empty file")
        os.chmod(dest, 0o444)
        name = Path(file.filename.replace("\\", "/")).name[:255] or "firmware.bin"
        name = "".join(c for c in name if c.isprintable())
        scan = Scan(id=scan_id, original_filename=name, stored_path=str(dest), size=size, sha256=h.hexdigest(),
                    status="queued", stage="queued", progress=0)
        db.add(scan)
        db.add(ScanEvent(scan_id=scan_id, stage="upload", message=f"Uploaded {name} ({size:,} bytes, "
                                                                   f"sha256 {h.hexdigest()[:16]}...)"))
        db.commit()
        if "w" in worker_holder:
            worker_holder["w"].notify()
        previous = db.execute(select(func.count()).select_from(Scan).where(Scan.sha256 == scan.sha256,
                                                                           Scan.id != scan_id)).scalar()
        d = scan_to_dict(scan, include_findings=False)
        d["previous_scans_same_hash"] = previous
        return d

    @app.get("/api/scans")
    def list_scans(limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0), q: str | None = None,
                   status: str | None = None, sha256: str | None = None, db: Session = Depends(get_session)):
        stmt = select(Scan)
        if q:
            like = f"%{q}%"
            stmt = stmt.where(or_(Scan.original_filename.ilike(like), Scan.sha256.ilike(like)))
        if status:
            stmt = stmt.where(Scan.status == status)
        if sha256:
            stmt = stmt.where(Scan.sha256 == sha256.lower())
        total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar()
        rows = db.execute(stmt.order_by(Scan.created_at.desc()).limit(limit).offset(offset)).scalars().all()
        return {"total": total, "items": [scan_to_dict(s, include_findings=False) for s in rows]}

    def _get(db: Session, scan_id: str) -> Scan:
        scan = db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(404, "scan not found")
        return scan

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: str, db: Session = Depends(get_session)):
        scan = _get(db, scan_id)
        d = scan_to_dict(scan, include_findings=False)
        from .reports.export import tool_run_to_dict
        d["tool_runs"] = [tool_run_to_dict(t) for t in scan.tool_runs]
        d["events"] = [{"ts": e.ts.isoformat(), "level": e.level, "stage": e.stage, "message": e.message}
                       for e in scan.events[-200:]]
        d["finding_count"] = len(scan.findings)
        return d

    @app.get("/api/scans/{scan_id}/findings")
    def get_findings(scan_id: str, severity: list[str] | None = Query(None),
                     classification: list[str] | None = Query(None), tool: str | None = None,
                     q: str | None = None, db: Session = Depends(get_session)):
        _get(db, scan_id)
        stmt = select(FindingRow).where(FindingRow.scan_id == scan_id)
        if severity:
            stmt = stmt.where(FindingRow.severity.in_(severity))
        if classification:
            stmt = stmt.where(FindingRow.classification.in_(classification))
        if tool:
            stmt = stmt.where(FindingRow.source_tool == tool)
        if q:
            like = f"%{q}%"
            stmt = stmt.where(or_(FindingRow.title.ilike(like), FindingRow.affected_component.ilike(like),
                                  FindingRow.description.ilike(like)))
        rows = db.execute(stmt.order_by(FindingRow.severity_rank, FindingRow.title)).scalars().all()
        return {"items": [finding_to_dict(f) for f in rows]}

    @app.get("/api/scans/{scan_id}/artifacts")
    def get_artifacts(scan_id: str, limit: int = Query(500, ge=1, le=5000), offset: int = Query(0, ge=0),
                      category: str | None = None, db: Session = Depends(get_session)):
        scan = _get(db, scan_id)
        if not scan.manifest_path or not Path(scan.manifest_path).exists():
            return {"total": 0, "items": [], "links": []}
        man = json.loads(Path(scan.manifest_path).read_text())
        arts = man["extraction"]["artifacts"]
        if category:
            arts = [a for a in arts if a.get("category") == category]
        keep = ("id", "name", "display_path", "size", "sha256", "format", "format_description", "category",
                "parent_id", "depth", "origin", "mode", "extraction", "extraction_note", "elf")
        items = [{k: a.get(k) for k in keep} for a in arts[offset:offset + limit]]
        return {"total": len(arts), "items": items, "links": man["extraction"]["links"][:500],
                "link_count": man["extraction"].get("link_count", 0)}

    @app.post("/api/scans/{scan_id}/rescan", status_code=202)
    def rescan(scan_id: str, db: Session = Depends(get_session)):
        scan = _get(db, scan_id)
        if scan.status in ("queued", "running"):
            raise HTTPException(409, "scan is already queued or running")
        scan.status, scan.stage, scan.progress, scan.error, scan.attempts = "queued", "queued", 0, None, 0
        scan.finished_at = None
        db.add(ScanEvent(scan_id=scan_id, stage="rescan", message="Re-scan requested"))
        db.commit()
        if "w" in worker_holder:
            worker_holder["w"].notify()
        return {"status": "queued"}

    @app.delete("/api/scans/{scan_id}", status_code=204)
    def delete_scan(scan_id: str, db: Session = Depends(get_session)):
        scan = _get(db, scan_id)
        if scan.status == "running":
            raise HTTPException(409, "cannot delete a running scan")
        Path(scan.stored_path).unlink(missing_ok=True)
        shutil.rmtree(settings.work_root / scan_id, ignore_errors=True)
        db.delete(scan)
        db.commit()
        return Response(status_code=204)

    @app.get("/api/scans/{scan_id}/report.json")
    def report_json(scan_id: str, db: Session = Depends(get_session)):
        scan = _get(db, scan_id)
        body = json.dumps(json_report(scan), indent=2)
        return Response(body, media_type="application/json", headers={
            "Content-Disposition": f'attachment; filename="dfa-report-{scan_id[:8]}.json"'})

    @app.get("/api/scans/{scan_id}/report.pdf")
    def report_pdf(scan_id: str, db: Session = Depends(get_session)):
        scan = _get(db, scan_id)
        if scan.status != "completed":
            raise HTTPException(409, "report is available once the scan has completed")
        return Response(pdf_report(scan), media_type="application/pdf", headers={
            "Content-Disposition": f'attachment; filename="dfa-report-{scan_id[:8]}.pdf"'})

    @app.get("/api/compare")
    def compare_scans(base: str, target: str, db: Session = Depends(get_session)):
        from .compare import compare
        a, b = _get(db, base), _get(db, target)
        if a.status != "completed" or b.status != "completed":
            raise HTTPException(409, "both scans must be completed")
        return compare(a, b)

    # ------------------------------------------------------------- frontend
    dist = Path(os.environ.get("DFA_FRONTEND_DIST", Path(__file__).resolve().parents[2] / "frontend" / "dist"))
    if dist.is_dir():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str):
            if path.startswith("api/"):
                raise HTTPException(404)
            f = (dist / path).resolve()
            if path and f.is_file() and f.is_relative_to(dist.resolve()):
                return FileResponse(f)
            return FileResponse(dist / "index.html")

    return app


def app_factory() -> FastAPI:  # for `uvicorn dfa.main:app_factory --factory`
    logging.basicConfig(level=logging.INFO)
    return create_app()
