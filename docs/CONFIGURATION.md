# Configuration

All settings are environment variables with the prefix `DFA_`. They are also
read from `backend/.env` (gitignored), which `make run` and `make dev-api`
load. Settings are read once at startup, so restart the app after changing
them.

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
| `DFA_KEEP_EXTRACTED` | `true` | `false` deletes extracted files after each scan (manifest, findings and tool output are kept) |
| `DFA_CWE_CHECKER_IMAGE` / `_BIN` / `_MAX_BINARIES` / `_TIMEOUT_S` / `_BARE_METAL` | `ghcr.io/fkie-cad/cwe_checker:stable` / – / 5 / 900 / false | cwe_checker |
| `DFA_FWANALYZER_BIN` / `_TIMEOUT_S` | – / 600 | FwAnalyzer outside the sandbox image |
| `DFA_COMPONENT_KB` | – | Extra JSON knowledge-base entries for outdated components |
| `DFA_CVE_LOOKUP_ENABLED` | `true` | Match components against the local CVE database |
| `DFA_CVE_DB_PATH` | `<data>/cve.db` | CVE database location (`python -m dfa.cve update --db PATH` builds elsewhere) |
| `DFA_CVE_DB_MAX_AGE_DAYS` | 30 | Older NVD data is still used, with an "out of date" warning |

## Apple Silicon

cwe_checker's `:stable` image has no arm64 build. Use `:latest`, which tracks
upstream master:

```
DFA_CWE_CHECKER_IMAGE=ghcr.io/fkie-cad/cwe_checker:latest
```

## Large images

Full SD-card or eMMC images (several GB) exceed the default upload and
extraction limits. For images up to about 8 GB:

```
DFA_MAX_UPLOAD_MB=8192
DFA_MAX_EXTRACT_TOTAL_MB=16384
DFA_MAX_EXTRACT_FILE_MB=8192
DFA_SANDBOX_MEMORY=4g
DFA_SANDBOX_TIMEOUT_S=3600
```

Docker Desktop's VM needs more memory than `DFA_SANDBOX_MEMORY`. Expect
roughly twice the image size in disk use under `DFA_DATA_DIR` while
`DFA_KEEP_EXTRACTED=true`.
