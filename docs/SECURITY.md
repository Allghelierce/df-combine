# Security model

Uploaded firmware is **untrusted input**, and so is everything derived from it (extracted files, the
analysis manifest, tool output). The design goals: a malicious upload cannot execute code on the
host, escape its work directory, exhaust the host or reach the network, and a compromise of the
parts that handle untrusted data does not hand over the host.

## Never executed

No uploaded or extracted content is executed. Parsing is done by Python (`zipfile`, `tarfile`,
custom parsers for Intel HEX, PX4/APJ JSON, cpio, ROMFS, CROMFS, CramFS, DfuSe, MBR/GPT, uImage,
Android sparse, ESP images, PLF, IM\*H, LZ4/LZO/Zstandard streams), pyelftools and well-known
unpackers that only read data. cwe_checker and Ghidra *analyse* machine code statically; they do
not run it.

## Process topology and privileges

```
 browser ──HTTPS(reverse proxy)──► API + worker (uid 10002)          no Docker client, no Docker socket
                                        │ Unix socket (group 10002, mode 660, optional bearer token)
                                        ▼
                                  sandbox broker                    the only Docker client
                                        │ docker run (fixed profiles)
                                        ▼
          dfa-sandbox · cwe_checker · Ghidra containers            --network none, read-only, no caps
```

**Before** (MVP): the worker mounted `/var/run/docker.sock`. Anyone who compromised the worker -
the process that post-processes attacker-influenced data - could start a privileged container and
own the host.

**Now:** the API and worker never talk to Docker. They ask the **broker** (`python -m dfa.broker`)
to run one of four job profiles for a scan:

| Profile | Image | Runs | Writable |
|---|---|---|---|
| `analyze` | `dfa-sandbox` | `python -m dfa.core.analyze` (identify, extract, built-in scanners) | `/work` (the scan's work dir) |
| `fwanalyzer` | `dfa-sandbox` | `fwanalyzer -cfg … -in … -out …` | `/work/tools/fwanalyzer` |
| `cwe_checker` | cwe_checker image | `cwe_checker <target> --json --quiet [--bare-metal-config …]` | `/work/tools/cwe_checker` |
| `ghidra` | cwe_checker image | `analyzeHeadless … -postScript DfaExport.java …` | `/work/tools/ghidra` |

The broker builds the complete `docker run` command itself. The request only names the profile, the
scan ID and a few typed parameters, and the broker validates them:

* scan IDs must be UUIDs whose upload and work directory exist in the data directory;
* paths must be inside `/work/` (or exactly `/in/firmware`), contain no `..` component and no
  component starting with `-`;
* Ghidra processors come from an allow-list; base addresses must be hex; limits are clamped;
* images, memory/CPU/PID limits, timeouts and the OCI runtime come from the **broker's**
  configuration, not from the request;
* request bodies are capped at 64 KiB; the socket is group-restricted, and a shared bearer token
  (`DFA_BROKER_TOKEN`) can be required in addition.

Every container gets `--network none --read-only --cap-drop ALL --security-opt no-new-privileges`,
`--memory/--memory-swap`, `--cpus`, `--pids-limit`, `--ulimit core=0`, `--ulimit nofile`,
`--ulimit fsize`, tmpfs scratch space, a non-root UID (10001 for the sandbox image, 1000 for the
cwe_checker/Ghidra image), the firmware mounted read-only, and only its own writable directory. The
broker enforces a wall-clock timeout and a per-scan disk cap (`DFA_MAX_WORK_DIR_MB`, container
killed when exceeded) and limits concurrent containers (`DFA_SANDBOX_MAX_JOBS`).

Ownership hand-over: before a job the broker gives the job's writable directory to the container
UID; after the container has exited it gives it back to the owner of the work root (the worker), so
an unprivileged worker can read and delete results. Both passes use `lchown` and never follow links
(the tree may contain attacker-chosen symlinks), and they run only while no container uses the
directory.

**What a compromised API/worker can do now:** run the four analysis profiles on scans in the data
directory, read and alter scan data. It cannot start arbitrary containers, mount host paths, enable
networking, or change limits or images.

**What compromised analysis code (e.g. an exploited unpacker) can do:** read the firmware and write
into its own scan's work directory inside a network-less, capability-less, resource-limited
container. Its output (manifest, tool JSON) is treated as untrusted by the worker: paths are
re-validated to stay inside the work directory before any tool uses them.

### Docker Compose

`docker-compose.yml` implements this split: only the `broker` service mounts the Docker socket; it
has no network (`network_mode: none`), a read-only root filesystem and only the `CHOWN`,
`DAC_OVERRIDE` and `FOWNER` capabilities (for the ownership hand-over). `api` and `worker` run as
UID 10002 with `cap_drop: ALL`, read-only root filesystems and only the broker socket volume. This
topology was verified end to end in development: an unprivileged worker drove real scans through a
containerised broker (sandbox, FwAnalyzer, cwe_checker, Ghidra and FACT all completed).

### Stronger isolation: rootless Docker, gVisor, VMs

The broker is still root-equivalent on a host running a rootful Docker daemon (anyone controlling
the broker could ask *Docker* for anything). Options to shrink that, in increasing strength:

* **Rootless Docker / Podman for the broker's daemon.** Containers and the daemon then run in a
  user namespace of an unprivileged account; a container escape lands in that account, not root.
  Requires cgroup v2 with systemd delegation for `--memory/--cpus/--pids-limit` to work. Point the
  broker at the rootless socket (`DOCKER_HOST=unix:///run/user/<uid>/docker.sock`).
* **gVisor (`runsc`)** as the OCI runtime for analysis containers (`DFA_SANDBOX_RUNTIME=runsc`): the
  untrusted parsers then talk to gVisor's user-space kernel instead of the host kernel. Supported by
  configuration; **not verified here** (installing runsc in the development environment was not
  permitted).
* **A dedicated analysis VM** running the Docker daemon, the broker and the data directory, with the
  API on another machine. This is the strongest boundary and the recommended deployment for
  processing third-party firmware at scale. (The broker currently speaks over a Unix socket; a
  cross-host deployment needs the data directory and the socket shared, or the worker co-located
  with the broker in the VM.)

Kernel-level container escapes are outside what container isolation can prevent; use gVisor or a VM
boundary for hostile samples.

## Authentication, authorisation and upload handling

* **Users and roles** (`viewer`: read; `analyst`: upload and manage own scans; `admin`: everything,
  user management). The first admin is created from `DFA_BOOTSTRAP_ADMIN(_PASSWORD)` or with
  `python -m dfa.cli create-user`. Passwords: scrypt with per-user salt, minimum 10 characters.
* **Sessions:** opaque random tokens, stored only as hashes, 12-hour lifetime, HttpOnly
  `SameSite=Strict` cookie (`Secure` with `DFA_SESSION_COOKIE_SECURE=true`); state-changing requests
  require the `X-DFA-CSRF` header. **API tokens** for automation: bearer tokens, hashed at rest,
  with expiry, revocable. Failed logins are throttled per username and client address.
* **Visibility:** analysts see their own scans; viewers and admins see all; only the owner or an
  admin can re-scan or delete.
* **Uploads:** require authentication and the analyst role; `Content-Length` is checked against
  `DFA_MAX_UPLOAD_MB` **before** the multipart body is spooled and the streamed body is counted
  (HTTP 411/413); per-user rate (`DFA_UPLOAD_RATE_PER_HOUR`) and active-scan limits; uploads are
  refused when free disk space is below `DFA_MIN_FREE_DISK_MB`. Files are stored as `<uuid>.bin`
  (mode 0444); the client file name is reduced to a printable basename and only used as metadata.
* **Responses:** CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`; report
  downloads are attachments; the SPA static route cannot escape the build directory.

## Extraction guards (inside the sandbox, and in the local fallback)

* member names normalised; absolute paths re-rooted; `..`, NUL, drive letters and over-long names
  rejected; output paths re-checked to resolve inside the extraction root;
* symlinks, hardlinks, device nodes and FIFOs are **never created** - they are recorded in the
  manifest; external unpacker output is walked and such entries removed;
* files created with `O_EXCL|O_NOFOLLOW`, mode 0644 (setuid/setgid recorded, never applied);
* budgets: total bytes, per-file bytes, file count, nesting depth, per-member compression ratio,
  carve count; declared sizes are never trusted; partial files are deleted when a limit trips;
  xz/lzma decoders have a memory limit; CROMFS/CramFS/PLF/IM\*H/ESP parsers bound every offset and
  detect loops;
* ext2/3/4 is not unpacked with `debugfs rdump` (it writes through symlinks it created); each regular
  file is dumped individually to a path we created;
* ubi_reader and jefferson (which may follow links they create) run only inside the container;
* external unpackers run with `RLIMIT_FSIZE`/`RLIMIT_CPU`, a wall-clock timeout and an output-size
  watchdog;
* encrypted or signed vendor containers (e.g. DJI IM\*H modules) are reported, never decrypted.

## Local fallback

`DFA_SANDBOX_MODE=local` (or `auto` without Docker) runs the analysis in a separate interpreter with
`RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_FSIZE`, no core dumps and a minimal environment. It is **not**
container isolation; the UI shows a warning banner and each scan records its isolation mode.
`DFA_ALLOW_UNSANDBOXED=false` refuses scans instead. In this mode external engines run only if they
are installed on the host (`DFA_FWANALYZER_BIN`, `DFA_CWE_CHECKER_BIN`, or `fwanalyzer` on `PATH`),
and their tool status then says "NOT container-isolated".

## Review and tests

An adversarial review of extractor, sandbox runner, API and adapters was done with proof-of-concept
inputs; verified issues are fixed and covered by `tests/test_extract_security.py`,
`tests/test_sandbox.py` (profile contract, hardened command, ownership hand-over without following
links), `tests/test_auth.py` and `tests/test_api.py`.

## Residual risks / operator notes

* The broker is root-equivalent with a rootful Docker daemon; run it on a dedicated analysis host/VM
  or with a rootless daemon / gVisor.
* SQLite and local storage: single node. Put the API behind a TLS-terminating reverse proxy and set
  `DFA_SESSION_COOKIE_SECURE=true`.
* FACT is a separate service with its own security model; only submit firmware you are allowed to
  share with that instance.
