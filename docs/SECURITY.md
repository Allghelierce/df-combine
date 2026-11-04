# Security model

Uploaded firmware is **untrusted input**. The design goal is that a malicious
upload cannot execute code, escape the extraction directory, exhaust the host,
or reach the network.

## Never executed
No uploaded or extracted content is executed. Parsing is done by Python
(`zipfile`, `tarfile`, custom parsers for Intel HEX, PX4/APJ JSON, cpio, romfs,
DfuSe, MBR/GPT, uImage), pyelftools, and well-known unpackers
(`unsquashfs`, `debugfs rdump`, `mcopy`) that only read data.

## Layers of isolation

1. **Upload handling** (API): streamed to disk with a hard size limit
   (`DFA_MAX_UPLOAD_MB`, HTTP 413 above it), stored as `<uuid>.bin` with mode
   0444; the client file name is reduced to a printable basename and only used
   as metadata.
2. **Sandbox container per scan** (`DFA_SANDBOX_MODE=docker|auto`):
   `--network none`, `--read-only` root filesystem, `--tmpfs /tmp` (noexec),
   `--cap-drop ALL`, `--security-opt no-new-privileges`, memory/swap/CPU/PID
   limits, never root (UID 10001 if the worker itself runs as root), firmware
   mounted read-only, only the scan's work directory writable. FwAnalyzer also
   runs in this container.
3. **In-process extraction guards** (apply even without Docker):
   * member names normalised; absolute paths are re-rooted, `..`, NUL, drive
     letters and over-long names rejected; output paths are re-checked to
     resolve inside the extraction root;
   * symlinks, hardlinks, device nodes and FIFOs are **never created** — they
     are recorded in the manifest (`links`) for analysis; external unpacker
     output is walked afterwards and any such entries are removed;
   * files are created with `O_EXCL|O_NOFOLLOW`, mode 0644 (setuid/setgid bits
     are recorded as metadata, never applied);
   * budgets: total bytes (`DFA_MAX_EXTRACT_TOTAL_MB`), per-file bytes,
     file count, nesting depth, per-member compression ratio
     (`DFA_MAX_COMPRESSION_RATIO`, applied above 10 MiB), carve count; data is
     streamed and declared sizes are never trusted; partially written files
     are deleted when a limit trips;
   * external unpackers run with `RLIMIT_FSIZE`/`RLIMIT_CPU`, a wall-clock
     timeout and a watchdog on the output directory size.
4. **Local fallback** (`DFA_SANDBOX_MODE=local`, or `auto` without Docker):
   a separate interpreter with `RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_FSIZE`,
   no core dumps and a minimal environment. This is **not** container
   isolation; the UI shows a warning banner and every scan records the
   isolation mode. Set `DFA_ALLOW_UNSANDBOXED=false` to refuse scans instead.

## Residual risks / operator notes
* The worker talks to the Docker daemon (socket mount in `docker-compose.yml`),
  which is root-equivalent on the host. Run the stack on a dedicated analysis
  host/VM, or replace Docker with rootless Docker/Podman or gVisor (`runsc`).
* Kernel-level container escapes are out of scope for container isolation;
  for hostile samples use a VM boundary.
* `unsquashfs`/`debugfs`/`mcopy`/FwAnalyzer parse attacker-controlled
  filesystems; they run inside the sandbox container in Docker mode.
* The API has optional shared-key auth (`DFA_API_KEY`) and binds to
  127.0.0.1 by default; it is not a multi-tenant system. Put it behind an
  authenticating reverse proxy with TLS for shared use.
* Reports contain redacted secrets (prefix + length) and hashes of key
  material, not the secrets themselves. Raw extracted files remain in
  `DFA_DATA_DIR/work/<scan>` until the scan is deleted.

## Result integrity
Findings carry a `classification` that the code base never upgrades to
"confirmed": `detected` (factual evidence present; exploitability not
verified), `suspicious` (heuristic), `unverified` (version-based or
static-analysis warning), `info`. Reports state that absence of findings does
not imply absence of vulnerabilities.
