# Architecture

```
frontend/ (React + TS, Vite)          backend/dfa/
  Upload / Scans / Scan / Compare /     main.py        FastAPI app, upload, reports, static UI
  Tools                                 worker.py      SQLite-backed job queue (atomic claim, stale recovery)
            │  /api                     pipeline.py    sandbox stage → adapters → correlate → persist
            ▼                           sandbox.py     docker run --network none … / rlimit fallback
  FastAPI ──► SQLite (scans, findings,  toolexec.py    runs tools (FwAnalyzer) inside the sandbox image
             tool_runs, events)         core/          ← the only code that touches firmware bytes
            │                             analyze.py   sandbox entry point → manifest.json
            ▼                             identify.py  format, platform, architecture detection
  per-scan sandbox container              extract.py   safe recursive extractor + carving
  (dfa-sandbox image)                     formats/     ihex, px4/apj, cortex-m, elf, cpio/romfs/dfu/mbr/gpt
     identify → extract → scan            scanners/    secrets, configs, drone, binaries, components
     → manifest.json                    cve/           CVE database build, store and matching
            │                           adapters/      cve_lookup, fwanalyzer, cwe_checker (+ registry)
            ▼                           reports/       JSON + PDF (reportlab)
  adapters: CVE lookup (in app), FwAnalyzer (in sandbox), cwe_checker (own container)
```

**Why not Celery/Redis?** A single-node MVP needs durable jobs, progress and
crash recovery but not a broker. Jobs are rows in `scans`; workers claim them
with an atomic conditional `UPDATE`, so several worker threads/processes can
share the DB. Swapping in Celery later only touches `worker.py`.

**Adding a platform:** append a `PlatformSignature` in `core/identify.py`
(strong/weak byte signatures, version/vehicle regexes) and, if needed, a
scanner in `core/scanners/`.

**Adding a tool:** subclass `ToolAdapter` (`status`, `plan`, `run`) and
register it in `adapters/registry.py`.

## Layout

```
backend/        FastAPI app, analysis core, adapters, tests
frontend/       React + TypeScript dashboard
docker/         sandbox and app images
docs/           tool notes, configuration, security model, screenshots
scripts/        fixture generator
```

## API

OpenAPI docs are served at `/api/docs`. Main endpoints:

* `POST /api/scans` (multipart `file`) → scan (queued)
* `GET /api/scans?q=&status=&sha256=&limit=&offset=` – history
* `GET /api/scans/{id}` – status, progress, identification, tool runs, events
* `GET /api/scans/{id}/findings?severity=&classification=&tool=&q=`
* `GET /api/scans/{id}/artifacts` – extracted inventory and recorded links
* `GET /api/scans/{id}/report.json`, `GET /api/scans/{id}/report.pdf`
* `POST /api/scans/{id}/rescan`, `DELETE /api/scans/{id}`
* `GET /api/compare?base={id}&target={id}` – diff two completed scans
* `GET /api/tools`, `GET /api/stats`, `GET /api/config`, `GET /api/health`

## Test fixtures

The backend suite generates synthetic fixtures at runtime
(`backend/tests/factory.py`): PX4 `.px4` with an embedded ROMFS `rcS`,
ArduPilot `.apj`/`.hex`/raw `.bin` with a gzip-compressed `defaults.parm` and
the AP app-descriptor signature, a companion rootfs as `.tar.gz`, `.zip`,
SquashFS, ext4 and an MBR SD-card image, an unhardened ELF compiled on the
fly, and malicious archives (zip-slip, tar traversal/symlink/hardlink/device,
nested archives, zip/gzip bombs). No proprietary firmware is downloaded or
included; the "private keys" are random bytes in PEM armour. Docker-dependent
tests (sandbox, FwAnalyzer-in-sandbox, no-network check) run when
`dfa-sandbox:latest` exists and are skipped otherwise.
