# Drone Firmware Analyzer

Upload drone firmware and get an automated **static** security analysis report.
PX4 and ArduPilot flight-controller firmware and Linux companion-computer images
are first-class targets; the platform/format registries are designed so other
drone platforms can be added.

![Dashboard](docs/img/dashboard.png)

## What it does

| Stage | Details |
|---|---|
| **Upload** | Drag-and-drop UI or `POST /api/scans`. Streamed with a size limit, hashed (SHA-256), never executed. |
| **Identification** | Format detected from content (extensions are ignored): ELF, ZIP, tar, gzip/bzip2/xz (incl. `.tar.gz`), Intel HEX, PX4 `.px4`, ArduPilot `.apj`, DfuSe `.dfu`, U-Boot uImage, cpio, ROMFS, SquashFS, ext2/3/4, FAT, UBI/UBIFS and JFFS2 (container sandbox only), LZMA, MBR/GPT disk images (`.img`), raw ARM Cortex-M flash images. Platform (PX4, ArduPilot, Betaflight, INAV, Linux companion), version, vehicle type, board ID, architecture, OS, entropy. |
| **Extraction** | Recursive, with path-traversal/symlink/device protection and size/count/depth/ratio budgets. Carves embedded ROMFS (PX4 init scripts), gzip streams (ArduPilot ROMFS files), SquashFS, uImage, cpio and ELF objects from raw images. Partition tables are split into partitions. |
| **Scanning** | Built-in: hardcoded credentials, private keys, tokens, `/etc/shadow` issues, Wi-Fi PSKs, insecure services (telnet, root SSH, autologin…), PX4 circuit breakers / ArduPilot safety parameters, MAVLink exposure (mavlink-router, MAVProxy), ELF hardening (NX/PIE/RELRO/canary), dangerous imports, suspicious strings, outdated components (offline knowledge base). External: **FwAnalyzer**, **cwe_checker**, **FACT** through modular adapters. |
| **Normalisation** | One schema for every tool: severity, classification, confidence, evidence, affected component, source tool, CWE, remediation. Duplicates across tools are merged and credited (`corroborated-by:<tool>`). |
| **Reporting** | Live dashboard (progress, findings, severity breakdown, metadata, inventory, components, activity log), JSON and PDF export, searchable scan history, re-scan, and **release comparison** (new / resolved / severity-changed findings and component version changes between two scans). |

### Honest findings
Every finding has a **classification**:

* `detected` – concrete evidence was found (e.g. an unencrypted PEM key, `root::` in `/etc/shadow`, `PermitRootLogin yes`). Exploitability is **not** verified.
* `suspicious` – heuristic/pattern match; may be a false positive.
* `unverified` – needs manual confirmation (version-string CVE matches, cwe_checker/FACT warnings).
* `info` – context.

Nothing is ever labelled "confirmed vulnerability". Tools that are not installed,
not configured, not applicable to the firmware, or that fail are shown as such
on every scan — never silently skipped.

![Scan detail](docs/img/scan.png)

## Quick start (development)

Requirements: Python ≥ 3.11, Node ≥ 20, optional Docker. For full extraction
coverage outside Docker install `squashfs-tools e2fsprogs mtools` (and `e2tools cpio` for
FwAnalyzer on the host); the sandbox image bundles all unpackers including
ubi_reader and jefferson.

```bash
make install              # venv + backend deps + frontend deps
```

```bash
make sandbox-image        # optional but recommended: builds dfa-sandbox:latest (includes FwAnalyzer)
```

```bash
make fixtures             # synthetic PX4/ArduPilot/companion/malicious samples -> fixtures/generated/
```

Run API + worker + built UI in one process on http://127.0.0.1:8000:

```bash
make run
```

Or with hot reload (API on :8000, Vite dev server on :5173 proxying `/api`):

```bash
make dev-api
```

```bash
make dev-ui
```

Without the sandbox image the app still works but uses the **local
rlimit-only fallback** and shows a warning banner (see
[docs/SECURITY.md](docs/SECURITY.md)).

### Docker Compose (single node)

```bash
docker compose up --build
```

This builds `dfa-sandbox:latest`, the app image (API + UI), and a separate
worker. Data lives in `./var`. The worker uses the host Docker socket to start
a network-less sandbox container per scan — read the residual-risk notes in
[docs/SECURITY.md](docs/SECURITY.md) before exposing it.

To enable the optional tools:

```bash
docker pull ghcr.io/fkie-cad/cwe_checker:stable           # cwe_checker
```

```bash
DFA_FACT_URL=http://fact-host:5000 docker compose up -d    # FACT (separately deployed)
```

## Configuration

Environment variables (prefix `DFA_`, also read from `backend/.env`):

| Variable | Default | Meaning |
|---|---|---|
| `DFA_DATA_DIR` | `backend/var` | Uploads, work directories, SQLite DB |
| `DFA_DATABASE_URL` | `sqlite:///<data>/dfa.db` | SQLAlchemy URL |
| `DFA_MAX_UPLOAD_MB` | 512 | Upload limit (HTTP 413 above) |
| `DFA_API_KEY` | – | If set, required as `X-API-Key` |
| `DFA_WORKER_MODE` | `inprocess` | `inprocess` (worker threads in the API) or `external` (`python -m dfa.worker`) |
| `DFA_WORKER_THREADS` | 1 | Concurrent scans per worker |
| `DFA_SANDBOX_MODE` | `auto` | `docker`, `local`, or `auto` (Docker if image present) |
| `DFA_ALLOW_UNSANDBOXED` | `true` | Allow the local fallback in `auto` mode |
| `DFA_SANDBOX_IMAGE` / `_MEMORY` / `_CPUS` / `_PIDS` / `_TIMEOUT_S` | `dfa-sandbox:latest` / `2g` / `2` / 256 / 1800 | Sandbox container settings |
| `DFA_SANDBOX_HOST_DATA_DIR` | – | Host path of `DFA_DATA_DIR` when the worker itself runs in a container |
| `DFA_MAX_EXTRACT_TOTAL_MB` / `_FILE_MB` / `_FILES` / `_DEPTH` | 2048 / 512 / 20000 / 5 | Extraction budgets |
| `DFA_MAX_COMPRESSION_RATIO` | 250 | Per-member ratio limit (bomb protection) |
| `DFA_CWE_CHECKER_IMAGE` / `_BIN` / `_MAX_BINARIES` / `_TIMEOUT_S` / `_BARE_METAL` | ghcr image / – / 5 / 900 / false | cwe_checker |
| `DFA_FWANALYZER_BIN` / `_TIMEOUT_S` | – / 600 | FwAnalyzer outside the sandbox image |
| `DFA_FACT_URL` / `_API_KEY` / `_TIMEOUT_S` / `_MAX_UPLOAD_MB` | – / – / 3600 / 256 | FACT REST service |
| `DFA_COMPONENT_KB` | – | Extra JSON knowledge-base entries for outdated components |

## API

OpenAPI docs at `/api/docs`. Main endpoints:

* `POST /api/scans` (multipart `file`) → scan (queued)
* `GET /api/scans?q=&status=&sha256=&limit=&offset=` – history
* `GET /api/scans/{id}` – status, progress, identification, tool runs, events
* `GET /api/scans/{id}/findings?severity=&classification=&tool=&q=`
* `GET /api/scans/{id}/artifacts` – extracted inventory and recorded links
* `GET /api/scans/{id}/report.json`, `GET /api/scans/{id}/report.pdf`
* `POST /api/scans/{id}/rescan`, `DELETE /api/scans/{id}`
* `GET /api/compare?base={id}&target={id}` – diff two completed scans
* `GET /api/tools`, `GET /api/stats`, `GET /api/config`, `GET /api/health`

## Architecture

```
frontend/ (React + TS, Vite)          backend/dfa/
  Dashboard / History / Scan / Tools    main.py        FastAPI app, upload, reports, static UI
            │  /api                     worker.py      SQLite-backed job queue (atomic claim, stale recovery)
            ▼                           pipeline.py    sandbox stage → adapters → correlate → persist
  FastAPI ──► SQLite (scans, findings,  sandbox.py     docker run --network none … / rlimit fallback
             tool_runs, events)         toolexec.py    runs tools (FwAnalyzer) inside the sandbox image
            │                           core/          ← the only code that touches firmware bytes
            ▼                             analyze.py   sandbox entry point → manifest.json
  per-scan sandbox container              identify.py  format, platform, architecture detection
  (dfa-sandbox image)                     extract.py   safe recursive extractor + carving
     identify → extract → scan            formats/     ihex, px4/apj, cortex-m, elf, cpio/romfs/dfu/mbr/gpt
     → manifest.json                      scanners/    secrets, configs, drone, binaries, components
            │                           adapters/      fwanalyzer, cwe_checker, fact (+ registry)
            ▼                           reports/       JSON + PDF (reportlab)
  adapters: FwAnalyzer (in sandbox), cwe_checker (own container), FACT (REST)
```

**Why not Celery/Redis?** A single-node MVP needs durable jobs, progress and
crash recovery but not a broker. Jobs are rows in `scans`; workers claim them
with an atomic conditional `UPDATE`, so several worker threads/processes can
share the DB. Swapping in Celery later only touches `worker.py`.

**Adding a platform:** append a `PlatformSignature` in `core/identify.py`
(strong/weak byte signatures, version/vehicle regexes) and, if needed, a
scanner in `core/scanners/`. **Adding a tool:** subclass `ToolAdapter`
(`status`, `plan`, `run`) and register it in `adapters/registry.py`.

## Tests

```bash
make test     # backend pytest (unit + integration) and frontend vitest + type-check
```

```bash
make lint
```

The backend suite generates synthetic fixtures at runtime (`backend/tests/factory.py`):
PX4 `.px4` with an embedded ROMFS `rcS`, ArduPilot `.apj`/`.hex`/raw `.bin` with a
gzip-compressed `defaults.parm` and the AP app-descriptor signature, a companion
rootfs as `.tar.gz`, `.zip`, SquashFS, ext4 and an MBR SD-card image, an
unhardened ELF compiled on the fly, and malicious archives (zip-slip, tar
traversal/symlink/hardlink/device, nested archives, zip/gzip bombs). No
proprietary firmware is downloaded or included; the "private keys" are random
bytes in PEM armour. Docker-dependent tests (sandbox, FwAnalyzer-in-sandbox,
no-network check) run when `dfa-sandbox:latest` exists and are skipped
otherwise.

## Limitations

See [docs/TOOLS.md](docs/TOOLS.md) for per-tool validation status. In short:

* **cwe_checker** could not be pulled in the build environment (registry
  blocked); its adapter is tested against schema-conformant output only.
  Bare-metal (PX4/ArduPilot MCU) analysis is experimental upstream and off by
  default.
* **FACT** is integrated via its REST API but was not tested against a live
  instance.
* **FwAnalyzer**'s ext2/3/4 backend crashes with stock e2tools; the adapter
  falls back to directory mode (without permission checks) and says so.
* UBI/UBIFS and JFFS2 are only unpacked inside the Docker sandbox (the
  unpackers may follow links); without it they are reported as not analysed.
* Not unpacked yet: LZ4/LZO/zstd payloads, 7z/RAR,
  encrypted/signed vendor containers (e.g. DJI), Android sparse images. These
  are identified and reported as "not fully analysed" findings.
* Outdated-component detection is version-string based against a small
  offline knowledge base (`as_of` dated); backported fixes are not detected,
  hence all such findings are `unverified`. No live CVE feed is queried.
* MCU firmware analysis (PX4/ArduPilot) is limited to identification,
  embedded files (init scripts, default parameters), strings and metadata; no
  disassembly-based checks run unless cwe_checker bare-metal mode is enabled.
* Single-node design (SQLite, local file storage); the API key is a single
  shared secret. Not hardened for multi-tenant or internet exposure.

## Project layout

```
backend/        FastAPI app, analysis core, adapters, tests
frontend/       React + TypeScript dashboard
docker/         sandbox and app images
docs/           tool research, security model, screenshots
scripts/        fixture generator
```
