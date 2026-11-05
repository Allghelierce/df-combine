"""Scan pipeline: sandboxed analysis -> tool adapters -> normalised findings in the DB."""
from __future__ import annotations

import json
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import delete

from . import safefs
from .adapters.base import AdapterContext
from .adapters.registry import get_adapters
from .config import Settings
from .core.findings import SEVERITY_ORDER, Finding, aggregate, attribute_packages, correlate, dedupe
from .db import session_scope
from .models import FindingRow, Scan, ScanEvent, ToolRun
from .sandbox import SandboxError, reset_workdir, run_analysis

SEVERITY_WEIGHT = {"critical": 40, "high": 15, "medium": 5, "low": 1, "info": 0}
CLASS_WEIGHT = {"detected": 1.0, "suspicious": 0.6, "unverified": 0.5, "info": 0.0}


def now() -> datetime:
    return datetime.now(UTC)


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
                    findings: int = 0, raw: str | None = None, details: dict | None = None,
                    duration: float | None = None) -> None:
    fin = now()
    with session_scope() as s:
        s.add(ToolRun(scan_id=scan_id, tool=tool, display_name=display, status=status, message=message[:4000],
                      started_at=started, finished_at=fin,
                      duration_s=duration if duration is not None else (fin - started).total_seconds(),
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
    work = reset_workdir(scan_id, settings)

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
        scan.packages = manifest.get("packages")
        scan.manifest_path = str(work / "manifest.json")
    iso_mode = res.isolation.split(":")[0]
    for run in manifest["scanner_runs"]:
        _store_tool_run(scan_id, run["name"], run["name"].replace("builtin:", "Built-in: "), run["status"],
                        run.get("error") or f"{run['findings']} finding(s); ran in {iso_mode} sandbox", started,
                        run["findings"], details={"isolation": res.isolation}, duration=run.get("duration_s"))
    findings = [Finding.from_dict(f) for f in manifest["findings"]]
    log_event(scan_id, "sandbox", f"Isolated analysis finished in {res.duration_s}s ({res.isolation}); "
                                  f"{len(ex['artifacts'])} artifacts, {len(findings)} built-in findings", progress=65)

    # ---- stage 2a: vulnerability intelligence (offline OSV database) ----
    t0 = now()
    from .vulndb import UPSTREAM, open_db
    db = open_db(settings)
    if db is None:
        _store_tool_run(scan_id, "osv", "Vulnerability database (OSV)", "unavailable",
                        "No offline vulnerability database. Build it with 'python -m dfa.vulndb update --download' "
                        "(Debian, Alpine and upstream GIT data from osv.dev); the built-in version baseline was used "
                        "instead.", t0)
    else:
        from .vulnmatch import match as vuln_match
        try:
            vfindings, vstats = vuln_match(manifest, db, name)
        except Exception as exc:  # noqa: BLE001
            _store_tool_run(scan_id, "osv", "Vulnerability database (OSV)", "failed", f"{type(exc).__name__}: {exc}", t0)
        else:
            # the offline OSV data supersedes the small built-in baseline for the components it covers
            findings = [f for f in findings if not (f.source_tool == "builtin:components"
                                                    and f.rule_id.removeprefix("outdated-") in UPSTREAM)]
            findings += vfindings
            ds = ", ".join(f"{k.split(':', 1)[1]} {v[:10]}" for k, v in vstats["dataset"].items()
                           if k.startswith("dataset:"))
            note = (f"; no OSV data for package managers: {', '.join(vstats['unmatched_managers'])}"
                    if vstats["unmatched_managers"] else "")
            _store_tool_run(scan_id, "osv", "Vulnerability database (OSV)", "completed",
                            f"checked {vstats['packages_checked']} distro packages and {vstats['components_checked']} "
                            f"upstream components: {vstats['affected']} affected, {vstats['vulnerabilities']} "
                            f"vulnerabilities (datasets: {ds}){note}", t0, len(vfindings), details=vstats)
            with session_scope() as s:
                sc = s.get(Scan, scan_id)
                sc.components = manifest["components"]
                sc.packages = manifest.get("packages")
            safefs.write_text(work, "manifest.json", json.dumps(manifest, indent=1, default=str))

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
        extra = [c for c in (r.details or {}).get("components", []) if c.get("name")]
        if extra:
            merged = {(c["name"], c.get("version", "")): c for c in manifest.get("components", [])}
            for c in extra:
                key = (c["name"], c.get("version", ""))
                if key in merged:
                    merged[key]["sources"] = list(dict.fromkeys(merged[key].get("sources", []) + c["sources"]))[:8]
                else:
                    merged[key] = c
            manifest["components"] = sorted(merged.values(), key=lambda c: (c["name"], c.get("version", "")))
            with session_scope() as s:
                s.get(Scan, scan_id).components = manifest["components"]
        _store_tool_run(scan_id, ad.name, ad.display_name, r.status, r.message, t0, len(r.findings),
                        r.raw_output_path, r.details)
        level = "info" if r.status in ("completed", "skipped") else "warning"
        log_event(scan_id, f"tool:{ad.name}", f"{ad.display_name}: {r.status} - {r.message}", level, progress=pct)

    # ---- stage 3: normalise + persist ----
    attributed = attribute_packages(findings, manifest.get("packages"))
    if attributed:
        log_event(scan_id, "packages", f"{attributed} finding(s) attributed to the installed package owning the file")
    final = [f.to_dict() for f in dedupe(aggregate(correlate(findings)))]
    sev = Counter(f["severity"] for f in final)
    cls = Counter(f["classification"] for f in final)
    with session_scope() as s:
        for f in final:
            s.add(FindingRow(scan_id=scan_id, fingerprint=f["fingerprint"], title=f["title"][:512],
                             description=f["description"], severity=f["severity"],
                             severity_rank=SEVERITY_ORDER.index(f["severity"]), classification=f["classification"],
                             confidence=f["confidence"], source_tool=f["source_tool"], rule_id=f["rule_id"],
                             affected_component=f["affected_component"], remediation=f["remediation"],
                             evidence=f["evidence"], cwe=f["cwe"], references=f["references"], tags=f["tags"],
                             package=f.get("package")))
        scan = s.get(Scan, scan_id)
        scan.severity_counts = {k: sev.get(k, 0) for k in SEVERITY_ORDER}
        scan.classification_counts = {k: cls.get(k, 0) for k in ("detected", "suspicious", "unverified", "info")}
        scan.risk_score = risk_score(final)
    safefs.write_text(work, "findings.json", json.dumps(final, indent=1))
    if not settings.keep_extracted:
        import shutil
        shutil.rmtree(work / "files", ignore_errors=True)
        log_event(scan_id, "cleanup", "Extracted files removed (DFA_KEEP_EXTRACTED=false); manifest and findings kept")
    log_event(scan_id, "complete", f"Scan complete: {len(final)} findings", progress=100)
