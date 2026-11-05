# External analysis engines: requirements, integration and validation evidence

Each engine decides per scan whether it *applies* to the firmware, and every scan records one of
`completed | failed | skipped (not applicable) | unavailable | timeout` with a message. All container
engines are started by the sandbox broker (see [SECURITY.md](SECURITY.md)) with `--network none`,
a read-only root filesystem, `--cap-drop ALL`, `no-new-privileges`, memory/CPU/PID/file-size limits,
a timeout and a per-scan disk cap; the firmware is mounted read-only.

| | FwAnalyzer | cwe_checker | Ghidra (headless) | FACT |
|---|---|---|---|---|
| Project | [cruise-automation/fwanalyzer](https://github.com/cruise-automation/fwanalyzer) | [fkie-cad/cwe_checker](https://github.com/fkie-cad/cwe_checker) | [NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra) | [fkie-cad/FACT_core](https://github.com/fkie-cad/FACT_core) |
| What it does | Rule checks on a filesystem tree | Rust + Ghidra P-Code analysis for CWE patterns | Disassembly, function recovery, call graph | Unpacking + plug-in analysis platform |
| Input used here | Extracted Linux rootfs (`dirfs`) or PX4 NuttX `/etc` (CROMFS) | One binary per run: ELF, or raw Cortex-M image with a bare-metal config | ELF, or raw Cortex-M image (base address + vector table) | Original upload + decoded images |
| How it runs | Inside `dfa-sandbox` | `fkiecad/cwe_checker:latest` (0.9.0, bundles Ghidra 11.2.1) | Same image, `analyzeHeadless` + our Java scripts | Separate service, REST API |
| Classification of results | `detected` / `suspicious` by rule | always `unverified` | `detected` only for `gets()` call sites, else `suspicious` / info | per plug-in; version-based = `unverified` |

## Real-input validation (development environment)

Inputs: official PX4 v1.17.0 builds (`px4-travis.s3.amazonaws.com`, pinned SHA-256), official ArduPilot
bootloader builds (committed in the ArduPilot repository, tag Copter-4.5.7), Debian 11 armhf
and Alpine 3.15 arm64 root filesystems exported from the official Docker images, esptool's published
ESP test images. Numbers are from actual runs, not mocks.

| Engine | Input | Result |
|---|---|---|
| cwe_checker | PX4 FMUv5 `.px4` → decoded 2 MB Cortex-M image + IO firmware + bootloader (bare-metal) | completed, 3/3 binaries in ~21–23 min; 4 grouped findings (CWE-125 ×3, CWE-787 ×10, CWE-476 ×157 warnings) |
| cwe_checker | PX4 CAN bootloader (bare-metal) | completed, 1 grouped finding |
| cwe_checker | ArduPilot AP_Bootloader for CubeOrange (bare-metal, STM32H7) | completed in 48 s, 1 grouped finding (CWE-476 ×2) |
| cwe_checker | Debian 11 armhf: `perl`, `libc-2.31.so`, `bash` | completed, 3/3 in 392 s, 28 grouped findings |
| cwe_checker | Alpine 3.15 arm64: `scanelf`, `apk`, `getent` | completed, 3/3, 14 grouped findings |
| cwe_checker | Debian `sbin/killall5` (imports `strcpy`) | completed; CWE-676 reported (`tests/test_real_tools.py`) |
| cwe_checker | PX4 unstripped debug ELF (47 MB) | **fails**: cwe_checker panics (upstream bug); the panic message is reported verbatim |
| Ghidra | PX4 FMUv5 image / IO / bootloader | completed: 8,258 / 363 / 110 functions (373–497 s) |
| Ghidra | Debian armhf `perl` / `libc` / `bash` | completed: 2,610 / 2,660 / 2,508 functions (542 s) |
| Ghidra | PX4 CAN bootloader | completed: 90 functions |
| Ghidra | ArduPilot CubeOrange bootloader | completed: 331 functions (18 s) |
| FwAnalyzer | Debian 11 / Alpine 3.15 rootfs (`dirfs`) | completed (no offenders with the default rule set) |
| FwAnalyzer | PX4 FMUv5 / FMUv2 CROMFS `/etc` (NuttX profile) | completed; FMUv5: 1 finding |
| FACT | PX4 `.px4` and decoded image; PX4 CAN bootloader; ArduPilot CubeOrange bootloader | completed end to end over REST; FACT's unpacker cannot unpack `.px4`/raw MCU images and no plug-in produced results — reported as such |
| FACT | Debian 11 rootfs | see the milestone report (run in progress at time of writing) |

Opt-in real integration tests (`DFA_REAL_TOOLS=1 pytest tests/test_real_tools.py`) cover FwAnalyzer
(Alpine, PX4 CROMFS), cwe_checker (ARM ELF, bare-metal), Ghidra (bare-metal) and FACT; all six pass
against the real tools. Mock-based tests in `tests/test_adapters.py` remain for unit coverage of
parsing and error handling.

## FwAnalyzer

* **Requirements:** Go build of `cmd/fwanalyzer` (pinned revision in `docker/sandbox.Dockerfile`),
  plus e2tools, squashfs-tools, mtools, ubi_reader, cpio for image mode. The project is no longer
  actively developed (last module version 2023-10).
* **Integration:** runs inside the network-less sandbox image, never on the host. The adapter writes
  a TOML rule set per scan: `Suid`, `WorldWrite`, `BadFiles`, `FileContent` regexes (empty
  passwords, `PermitEmptyPasswords yes`, telnetd in inittab) for files that exist. For PX4 NuttX
  `/etc` trees a **NuttX profile** checks init scripts for circuit-breaker overrides
  (`CBRK_IO_SAFETY 22027`, `CBRK_SUPPLY_CHK 894281`, `CBRK_USB_CHK 197848`, `CBRK_AIRSPD_CHK 162128`),
  MAVLink broadcast and safety-related settings.
* **Verified behaviour:** SquashFS image mode preserves setuid/world-writable bits; `Match = true`
  reports *matching* lines; ext2/3/4 image mode panics with stock e2tools (upstream needs a patched
  fork), so the adapter falls back to `dirfs`; FwAnalyzer omits empty `offenders`/`informational`
  keys from its JSON report.
* **Limitation:** in `dirfs` mode permission checks are off (extraction normalises modes); the
  built-in scanner checks setuid/world-writable bits from archive metadata instead.

## cwe_checker

* **Requirements:** x86-64 Docker image (Rust + Ghidra ≥ 10.2) or a local build. **Image/network
  findings:** `ghcr.io/fkie-cad/cwe_checker` could not be pulled from the development environment
  (registry blocked), `fkiecad/cwe_checker:latest` from Docker Hub works (0.9.0, Ghidra 11.2.1);
  Docker Hub rate limits (HTTP 429) occurred and were retried. cwe_checker needs no network at run
  time, so `--network none` is fine. Under a read-only root filesystem Ghidra needs writable
  `~/.config/ghidra`, `~/.ghidra`, `~/.cache` and `/tmp` (tmpfs mounts owned by UID 1000) and a
  resolvable hostname (`--hostname localhost`).
* **Supported inputs (verified):** 32-bit ARM and AArch64 ELF (dynamically linked userland), raw
  ARM Cortex-M images via `--bare-metal-config` (processor `ARM:LE:32:Cortex`, flash base estimated
  from the vector table and literal pools, RAM base/size from the initial SP). cwe_checker 0.9.0
  prints decimal addresses; hex addresses are taken from the TIDs.
* **Selection:** up to `DFA_CWE_CHECKER_MAX_BINARIES` binaries, prioritising network-facing and
  drone-related names; kernel modules are skipped.
* **Results** are grouped per (binary, CWE) and always `unverified` (upstream documents false
  positives/negatives; bare-metal mode is experimental upstream).

## Ghidra headless layer

* Uses `analyzeHeadless` from the cwe_checker image with two scripts in
  `backend/dfa/ghidra_scripts/`: `DfaCortexMVectors.java` (pre-script: seeds functions from the
  Cortex-M vector table of raw images, using the program's minimum address as the image base) and
  `DfaExport.java` (post-script: function count, named functions, instruction count, largest and most
  called functions, call sites of risky library functions).
* Raw images are imported with `-loader BinaryLoader -loader-baseAddr <flash base> -processor
  ARM:LE:32:Cortex`; the processor is validated against an allow-list.
* Findings: call sites of `gets` (`detected`, CWE-242), `system`/`popen` (`suspicious`), other risky
  calls (`low`). These are static observations, not confirmed vulnerabilities.

## FACT

* **Requirements:** FACT is a platform (frontend, backend, PostgreSQL, Redis, plug-in containers;
  4 cores / 8 GB RAM / 10 GB disk minimum upstream). It is integrated as an external service
  (`DFA_FACT_URL`, optional `DFA_FACT_API_KEY`).
* **Validated against a real FACT_core instance:** `PUT /rest/firmware` (base64 + metadata),
  completion via `GET /rest/status` (`system_status.backend.analysis.recently_finished_analyses` /
  `current_analyses`, unpacking queue), results via `GET /rest/firmware/<uid>?summary=true`;
  completion requires the `unpacker` analysis to be present. The installation needed patches
  for the environment (magic database built from source, Docker Hub image for the cwe_checker
  plug-in, binwalk and ip_and_uri_finder plug-ins disabled because they failed to install).
* **Behaviour notes:** FACT's uWSGI closes idle keep-alive connections, so the client uses a fresh
  connection per request and repeats an upload once after a dropped connection (FACT derives the
  UID from the content, so this is idempotent). `.px4` containers and raw MCU images are not
  unpackable by FACT; the adapter also submits the decoded images and says when no plug-in produced
  results.
* Normalisation maps `crypto_material`, `users_and_passwords`, `cve_lookup`, `known_vulnerabilities`,
  `cwe_checker` and `exploit_mitigations` summaries to findings; FACT's software components are
  merged into the component list.

## Vulnerability intelligence (built in)

* **Database:** `python -m dfa.vulndb update [--download | --source-dir DIR]` imports the public OSV
  dumps for Debian, Alpine and upstream GIT ranges into SQLite (`<data>/vulndb.sqlite`; ~84,000
  distro records and ~1,400 upstream records at the time of writing). OSV aggregates NVD CVE data
  for the GIT ecosystem; CVSS v3 base scores are computed from vectors in any record of the same CVE.
* **Distro packages (backport-aware):** dpkg/apk versions are compared with the distribution's
  fixed versions using dpkg/apk version ordering, so a backported fix (`1.1.1n-0+deb11u1`) is
  recognised. These findings are `detected` (the installed version is listed as affected).
* **Upstream components:** versions identified from strings or descriptors are matched to affected
  release tags (OpenSSL, BusyBox, Dropbear, dnsmasq, zlib, glibc, SQLite, OpenSSH, U-Boot, mbedTLS,
  hostapd/wpa_supplicant, lighttpd, uClibc-ng, curl, libpcap, NuttX, PX4, ArduPilot (per vehicle tag),
  ESP-IDF, FreeRTOS kernel, Zephyr). Always `unverified`: vendor backports are invisible. Components
  already covered by distro package data are not matched twice.
* **Ownership:** findings in files owned by an installed package name that package (dpkg/opkg file
  lists, apk installed database).
* **SBOM / exchange:** CycloneDX 1.5 (`/api/scans/{id}/sbom.cdx.json`) with purls and CPEs; SARIF 2.1.0
  (`/api/scans/{id}/report.sarif`).

## Built-in analyzers (always available)

Run inside the sandbox for every scan: format detection, safe recursive extraction and carving,
platform identification (PX4, ArduPilot, Betaflight, INAV, Espressif, DJI, Parrot, Linux companion),
architecture detection, secrets, insecure configuration, PX4/ArduPilot parameter and MAVLink exposure
checks, ELF hardening, component version strings and package inventories.
