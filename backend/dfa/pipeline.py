"""Scan pipeline: sandboxed analysis -> tool adapters -> normalised findings in the DB."""
from __future__ import annotations

import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import delete

from .adapters.base import AdapterContext
from .adapters.registry import get_adapters
from .config import Settings
from .core.findings import SEVERITY_ORDER, Finding, dedupe
from .db import session_scope
from .models import FindingRow, Scan, ScanEvent, ToolRun
from .sandbox import SandboxError, run_analysis

SEVERITY_WEIGHT = {"critical": 40, "high": 15, "medium": 5, "low": 1, "info": 0}
CLASS_WEIGHT = {"detected": 1.0, "suspicious": 0.6, "unverified": 0.5, "info": 0.0}


def now() -> datetime:
    return datetime.now(timezone.utc)


def log_event(scan_id: str, stage: str, message: str, level: str = "info", progress: int | None = None) -> None:
    with session_scope() as s:
        s.add(ScanEvent(scan_id=scan_id, stage=stage, message=message[:4000], level=level))
        scan = s.get(Scan, scan_id)
        if scan:
            scan.stage = stage
            scan.heartbeat_at = now()
            if progress is not None:
                scan.progress = max(scan.progress, progress)


def risk_score(findings: list[dict]) -> int:
    """0-100 heuristic summarising severity x evidence class (not a probability)."""
    total = sum(SEVERITY_WEIGHT[f["severity"]] * CLASS_WEIGHT[f["classification"]] for f in findings)
    return int(min(100, round(100 * (1 - 0.985 ** total))))


def _store_tool_run(scan_id: str, tool: str, display: str, status: str, message: str, started: datetime,
                    findings: int = 0, raw: str | None = None, details: dict | None = None) -> None:
    fin = now()
    with session_scope() as s:
        s.add(ToolRun(scan_id=scan_id, tool=tool, display_name=display, status=status, message=message[:4000],
                      started_at=started, finished_at=fin, duration_s=(fin - started).total_seconds(),
                      findings_count=findings, raw_output_path=raw, details=details or {}))


def process_scan(scan_id: str, settings: Settings) -> None:
    with session_scope() as s:
        scan = s.get(Scan, scan_id)
        if scan is None:
            return
        input_path = Path(scan.stored_path)
        name = scan.original_filename
        s.execute(delete(ToolRun).where(ToolRun.scan_id == scan_id))
        s.execute(delete(FindingRow).where(FindingRow.scan_id == scan_id))
    work = settings.work_root / scan_id
    if work.exists():
        import shutil
        shutil.rmtree(work)

    # ---- stage 1: sandboxed identification / extraction / built-in scanning ----
    log_event(scan_id, "sandbox", "Starting isolated analysis (identify, extract, built-in scanners)", progress=5)
    stage_progress = {"identify+extract": 10, "inventory": 40, "platform detection": 50, "components": 60}
    last = [0.0]

    def sb_progress(msg: str) -> None:
        if time.monotonic() - last[0] < 1.0 and msg not in stage_progress:
            return
        last[0] = time.monotonic()
        log_event(scan_id, "sandbox", msg[:300], progress=stage_progress.get(msg))

    started = now()
    try:
        res = run_analysis(input_path, name, work, settings, sb_progress)
    except SandboxError as exc:
        _store_tool_run(scan_id, "builtin", "Built-in analyzers", "failed", str(exc), started)
        raise
    manifest = res.manifest
    with session_scope() as s:
        scan = s.get(Scan, scan_id)
        scan.isolation = res.isolation[:64]
        scan.identification = manifest["identification"]
        ex = manifest["extraction"]
        scan.extraction_summary = {
            "artifact_count": len(ex["artifacts"]), "warnings": ex["warnings"][:100],
            "filesystems": ex["filesystems"], "limits_hit": ex["limits_hit"], "stats": ex["stats"],
            "rootfs": ex["rootfs"], "link_count": ex["link_count"],
            "categories": manifest["inventory"]["categories"], "isolation_detail": res.isolation,
        }
        scan.components = manifest["components"]
        scan.manifest_path = str(work / "manifest.json")
    for run in manifest["scanner_runs"]:
        _store_tool_run(scan_id, run["name"], run["name"].replace("builtin:", "Built-in: "), run["status"],
                        run.get("error") or f"{run['findings']} findings in {run['duration_s']}s", started,
                        run["findings"], details={"isolation": res.isolation})
    findings = [Finding.from_dict(f) for f in manifest["findings"]]
    log_event(scan_id, "sandbox", f"Isolated analysis finished in {res.duration_s}s ({res.isolation}); "
                                  f"{len(ex['artifacts'])} artifacts, {len(findings)} built-in findings", progress=65)

    # ---- stage 2: external tool adapters ----
    adapters = get_adapters(settings)
    for i, ad in enumerate(adapters):
        pct = 65 + int(30 * (i + 1) / len(adapters))
        log_event(scan_id, f"tool:{ad.name}", f"Running {ad.display_name}")
        ctx = AdapterContext(scan_id=scan_id, input_path=input_path, original_name=name, work_dir=work,
                             manifest=manifest, settings=settings,
                             log=lambda m, n=ad.name: log_event(scan_id, f"tool:{n}", m))
        t0 = now()
        r = ad.execute(ctx)
        findings += r.findings
        _store_tool_run(scan_id, ad.name, ad.display_name, r.status, r.message, t0, len(r.findings),
                        r.raw_output_path, r.details)
        level = "info" if r.status in ("completed", "skipped") else "warning"
        log_event(scan_id, f"tool:{ad.name}", f"{ad.display_name}: {r.status} - {r.message}", level, progress=pct)

    # ---- stage 3: normalise + persist ----
    final = [f.to_dict() for f in dedupe(findings)]
    sev = Counter(f["severity"] for f in final)
    cls = Counter(f["classification"] for f in final)
    with session_scope() as s:
        for f in final:
            s.add(FindingRow(scan_id=scan_id, fingerprint=f["fingerprint"], title=f["title"][:512],
                             description=f["description"], severity=f["severity"],
                             severity_rank=SEVERITY_ORDER.index(f["severity"]), classification=f["classification"],
                             confidence=f["confidence"], source_tool=f["source_tool"], rule_id=f["rule_id"],
                             affected_component=f["affected_component"], remediation=f["remediation"],
                             evidence=f["evidence"], cwe=f["cwe"], references=f["references"], tags=f["tags"]))
        scan = s.get(Scan, scan_id)
        scan.severity_counts = {k: sev.get(k, 0) for k in SEVERITY_ORDER}
        scan.classification_counts = {k: cls.get(k, 0) for k in ("detected", "suspicious", "unverified", "info")}
        scan.risk_score = risk_score(final)
    (work / "findings.json").write_text(json.dumps(final, indent=1))
    log_event(scan_id, "complete", f"Scan complete: {len(final)} findings", progress=100)
