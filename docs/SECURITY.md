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

The broker also owns the work root and is the only component that creates, resets or removes scan
directories, so the bind-mount source of a job is never a path the worker can replace.

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

A Docker daemon that cannot apply memory, PID or CPU limits only prints a warning and runs the
container without them (for example rootless Docker on cgroup v1, or on cgroup v2 without
delegation). The broker therefore reads `docker info` (`MemoryLimit`, `PidsLimit`, `CpuCfsQuota`,
registered runtimes) and **refuses jobs** when a limit cannot be enforced or when the configured
`DFA_SANDBOX_RUNTIME` is not registered; `/v1/capabilities` reports the daemon's state.

Ownership hand-over: before a job the broker gives the job's writable directory to the container
UID; after the container has exited it gives it back to the owner of the work root (the worker), so
an unprivileged worker can read and delete results. The worker owns these directories and could swap
any of them for a symlink (for example to the directory holding the Docker socket), so the broker
never resolves paths there: it opens each component with `O_NOFOLLOW | O_DIRECTORY` relative to the
work root's file descriptor, walks with `os.fwalk(follow_symlinks=False)` and changes ownership only
through directory file descriptors (`fchown`, `lchown` with `dir_fd`). A swapped component makes the
job fail instead of redirecting the broker. Scan directories and uploads that are symlinks are
refused before any container starts. When it hands a directory back, the broker also **removes every
entry that is neither a directory nor a regular file** (symlinks, FIFOs, sockets) from the whole
writable tree, `tools/` included: analysis output never contains links (the extractor records them in
the manifest instead), so any found were planted. It also clears group/other-write and setuid/setgid
bits, so a world-writable directory left by one job cannot be used by the next job's (different) UID
to write outside its own directory. A container the broker had to kill is force-removed before its
directory is handed back.

The upload is not mounted from `uploads/<id>.bin` (a path the API writes and could swap between the
broker's check and Docker's mount) but from a hard link the broker pins in `work/.inputs/` - inside
the broker-owned work root - after checking with `O_NOFOLLOW` that the source is a regular file.

The hand-back walk is **bottom-up** and changes each entry through a file descriptor opened with
`O_NOFOLLOW` (`fchmod`/`fchown`), never by path: a directory is given to the worker only after
everything below it is done, so the worker - a separate, live process - can never swap an entry the
broker is still working on. (An independent review found that an earlier, path-based version of the
mode clearing followed a symlink swapped in by the worker between the broker's `stat` and its `chmod`,
which let a compromised worker make the root broker change the mode of a host file; reproduced in
`tests/test_sandbox.py::test_hand_back_never_follows_a_link_swapped_in_mid_walk` and fixed.)

**What a compromised API/worker can do now:** run the four analysis profiles on scans in the data
directory, read and alter scan data. It cannot start arbitrary containers, mount host paths, enable
networking, or change limits or images.

**What compromised analysis code (e.g. an exploited unpacker) can do:** read the firmware and write
into its own scan's work directory inside a network-less, capability-less, resource-limited
container. Its output (manifest, tool JSON) is treated as untrusted by the worker: paths are
re-validated to stay inside the work directory before any tool uses them, and the worker and API
access the scan directory only through `dfa/safefs.py`:

* paths are walked component by component through directory fds with `O_NOFOLLOW`, so no planted
  symlink is followed, not even an intermediate one;
* only regular files are read, with size limits (a FIFO cannot block the worker, a link to
  `/dev/zero` cannot exhaust its memory). The manifest is capped at `DFA_MAX_MANIFEST_MB` (64 MiB; JSON
  grows about tenfold when parsed), deeply nested JSON is rejected, and its shape is checked before use,
  down to each finding's field types and enum values; lone surrogates (bytes that are not UTF-8) are
  shown as `\xNN`, so no sandbox output can break the database, the JSON API or the reports, and
  the UI turns only absolute http(s) references into links;
* JSON from untrusted sources (`.px4`/`.apj` containers, the manifest, cwe_checker, Ghidra,
  FwAnalyzer and FACT output) is parsed with `NaN`/`Infinity`, overflowing floats and integers of
  more than 40 digits as `null` (`dfa/core/safejson.py`): before, a container with `"board_id": NaN`
  made the scan unviewable (the API's JSON responses refuse non-finite floats), and a 5,000-digit
  integer would have made the whole container unreadable. API responses also send any non-finite
  float as `null` instead of failing;
* paths taken from the manifest (artifacts, filesystem roots, permission images) are resolved and must
  stay inside the work directory before any adapter uses them;
* progress messages from the sandbox are throttled and capped per poll;
* files the worker writes (`manifest.json`, `findings.json`, tool configs and outputs) are created
  under a fresh `O_EXCL` name and renamed over the target, which replaces a planted link instead of
  writing through it.

This closed a real hole: before the change, a sandbox that left `findings.json -> /data/dfa.db` made
the worker overwrite its SQLite database with the findings JSON (reproduced in
`tests/test_api.py::test_links_planted_by_a_compromised_sandbox_are_not_followed`, which fails
without the protection).

### Docker Compose

`docker-compose.yml` implements this split: only the `broker` service mounts the Docker socket; it
has no network (`network_mode: none`), a read-only root filesystem and only the `CHOWN`,
`DAC_OVERRIDE` and `FOWNER` capabilities (for the ownership hand-over). `api` and `worker` run as
UID 10002 with `cap_drop: ALL`, read-only root filesystems and only the broker socket volume. They
mount `./var/work` separately from `./var`: a mount point cannot be renamed, so even the worker cannot
move the broker-owned work root aside. API, worker and broker have memory limits
(`DFA_API_MEMORY`, `DFA_WORKER_MEMORY`, `DFA_BROKER_MEMORY`) and restart automatically; scans interrupted
by a restart are re-queued. A CA certificate for a TLS-intercepting proxy is passed to the
image builds as a BuildKit secret (`DFA_EXTRA_CA_CERT`), never copied into an image layer.

Verified in development with the images built from the published Dockerfiles: an unprivileged worker
drove real scans (PX4 `.px4` and unstripped ELF, Debian and Alpine root filesystems, ArduPilot builds)
through the containerised broker with the sandbox, FwAnalyzer, cwe_checker and Ghidra; deleting a scan
removed its directory, upload and pinned input. FACT was verified directly against a FACT instance on
the host; reaching that loopback-only instance from the compose network was not set up here.

### Stronger isolation: rootless Docker, gVisor, VMs

The broker is still root-equivalent on a host running a rootful Docker daemon (anyone controlling
the broker could ask *Docker* for anything). Options to shrink that, in increasing strength:

* **Rootless Docker / Podman for the broker's daemon.** Containers and the daemon then run in a
  user namespace of an unprivileged account; a container escape lands in that account, not root.
  Requires cgroup v2 with systemd delegation for `--memory/--cpus/--pids-limit` to work - otherwise
  the broker refuses jobs (see above). Point the broker at the rootless socket
  (`DOCKER_HOST=unix:///run/user/<uid>/docker.sock`). **Not verified here:** the development host
  uses cgroup v1, on which rootless Docker cannot enforce these limits at all.
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
  rejected; output paths re-checked to resolve inside the extraction root; bytes that are not UTF-8
  become a literal `\xNN` in the name on disk and in the manifest (tar, zip, external unpacker
  output), and a zip entry flagged UTF-8 whose name is not no longer makes the whole zip unreadable;
* content cannot be hidden from analysis behind a tar end-of-archive marker or a damaged tar header
  (reading continues, with a warning giving the bytes skipped), behind padding after a gzip, xz or
  zstd stream (0xFF padding used to fail the whole stream), in the later archives of an initramfs,
  after a uImage payload, a SquashFS image, a tar archive's end marker, any compressed stream or an
  executable's own data (ELF overlays; signed kernel modules are recognised),
  or under ext names that debugfs commands could not
  quote (listing and dumping go by inode number); data after a stream or image that is not padding
  is analysed as an artifact of its own, starting where the erased-flash padding ends;
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

Two independent adversarial reviews (extractor, sandbox runner, API and adapters; later the broker
hand-back, `safefs`, manifest handling and the new adapters) were done with proof-of-concept inputs;
verified issues are fixed and covered by `tests/test_extract_security.py`,
`tests/test_sandbox.py` (profile contract, hardened command, ownership hand-over without following
links, planted links removed, pinned upload), `tests/test_safefs.py` (no links followed, FIFOs,
size limits, replacing planted links), `tests/test_auth.py` and `tests/test_api.py`.

## Residual risks / operator notes

* The broker is root-equivalent with a rootful Docker daemon; run it on a dedicated analysis host/VM
  or with a rootless daemon / gVisor.
* Bind-mount sources are re-resolved by Docker when it creates a container. Neither can be swapped:
  the broker owns the work root (`root:root 0755`), creates, resets and removes scan directories
  itself (`/v1/workdirs`), and mounts the upload from a hard link it pinned in `work/.inputs/`. This
  needs the broker to run as root (as in Compose); a broker running as an ordinary docker-group user
  cannot own the work root, and then the upload is mounted from `uploads/<id>.bin` after an `lstat`
  check (a compromised API that wins that race could make a sandbox read a different host file,
  read-only, as a non-root user without capabilities).
* SQLite and local storage: single node. Put the API behind a TLS-terminating reverse proxy and set
  `DFA_SESSION_COOKIE_SECURE=true`.
* FACT is a separate service with its own security model; only submit firmware you are allowed to
  share with that instance.
