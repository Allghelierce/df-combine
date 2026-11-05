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
| Input used here | Permission image (cpio with original modes) of an extracted Linux rootfs, else `dirfs`; PX4 NuttX `/etc` (CROMFS) | One binary per run: ELF, or raw Cortex-M image with a bare-metal config (incl. the flash image derived from a Cortex-M ELF) | ELF, or raw Cortex-M image (base address + vector table) | Original upload, decoded images, tar of files extracted from CROMFS |
| How it runs | Inside `dfa-sandbox` | `fkiecad/cwe_checker:latest` (0.9.0, bundles Ghidra 11.2.1) | Same image, `analyzeHeadless` + our Java scripts | Separate service, REST API |
| Classification of results | `detected` / `suspicious` by rule | always `unverified` | `detected` only for `gets()` call sites, else `suspicious` / info | per plug-in; version-based = `unverified` |

## Real-input validation (development environment)

Inputs: official PX4 v1.17.0 builds (`px4-travis.s3.amazonaws.com`, pinned SHA-256), official ArduPilot
bootloader builds (committed in the ArduPilot repository, tag Copter-4.5.7), ArduPilot SITL vehicle
builds published for `dronekit-sitl`, official Betaflight and INAV release builds, Debian 11 armhf and
Alpine 3.15 arm64 root filesystems exported
from the official Docker images, esptool's published ESP test images. Numbers are from actual runs,
not mocks.

| Engine | Input | Result |
|---|---|---|
| cwe_checker | PX4 FMUv5 `.px4` → decoded 2 MB Cortex-M image + IO firmware + bootloader (bare-metal) | completed, 3/3 binaries in ~21–23 min; 4 grouped findings (CWE-125 ×3, CWE-787 ×10, CWE-476 ×157 warnings) |
| cwe_checker | PX4 CAN bootloader (bare-metal) | completed, 1 grouped finding |
| cwe_checker | ArduPilot AP_Bootloader for CubeOrange (bare-metal, STM32H7) | completed in 48 s, 1 grouped finding (CWE-476 ×2) |
| cwe_checker | Debian 11 armhf: `perl`, `libc-2.31.so`, `bash` | completed, 3/3 in 392 s, 28 grouped findings |
| cwe_checker | Alpine 3.15 arm64: `scanelf`, `apk`, `getent` | completed, 3/3, 14 grouped findings |
| cwe_checker | Debian `sbin/killall5` (imports `strcpy`) | completed; CWE-676 reported (`tests/test_real_tools.py`) |
| cwe_checker | PX4 FMUv2 unstripped ELF (23 MB) | cwe_checker 0.9.0 panics on the ELF itself (`fn_start_blocks.rs:44`, both with and without DWARF). The sandbox derives the flash image from the ELF's load segments - byte-identical (same SHA-256) to the image in the official `.px4` - and cwe_checker analyses it bare-metal: 3/3 binaries in the compose stack (main image 489 s, 101 warnings mapped to 57 named functions, 3 unresolved; IO firmware 25; bootloader 0) |
| Ghidra | PX4 FMUv5 image / IO / bootloader | completed: 8,258 / 363 / 110 functions (373–497 s) |
| Ghidra | PX4 FMUv2 unstripped ELF / IO / bootloader | completed: 6,366 / 363 / 112 functions (128 s in total) |
| Ghidra | Debian armhf `perl` / `libc` / `bash` | completed: 2,610 / 2,660 / 2,508 functions (542 s) |
| Ghidra | PX4 CAN bootloader | completed: 90 functions |
| Ghidra | ArduPilot CubeOrange bootloader | completed: 331 functions (18 s) |
| FwAnalyzer | Debian 11 rootfs (cpio permission image) | completed; 14 offenders of the Suid check: 8 setuid-root binaries (`su`, `mount`, `passwd`, ...), 4 setgid binaries (`unix_chkpwd`, `chage`, `expiry`, `wall`) and the setgid directories `/var/local`, `/var/mail` - FwAnalyzer labels all of them "File is SUID"; the evidence names the actual bit |
| FwAnalyzer | Alpine 3.15 rootfs (cpio permission image) | completed (no offenders) |
| FwAnalyzer | PX4 FMUv5 / FMUv2 CROMFS `/etc` (NuttX profile) | completed; FMUv5: 1 finding |
| FACT | PX4 `.px4` and decoded image; PX4 CAN bootloader; ArduPilot CubeOrange bootloader | completed end to end over REST; FACT's unpacker cannot unpack `.px4`/raw MCU images and no plug-in produced results — reported as such |
| FACT | PX4 FMUv5 `.px4`: upload, decoded image, tar of the files extracted from the `/etc` CROMFS | completed in 42 s; FACT analysed 1, 1 and 72 files; none of the requested plug-ins found anything in PX4 content (reported as such) |
| FACT | Debian 11 rootfs | with FACT's per-file cwe_checker plug-in requested (former default): did not finish within the 3,600 s timeout. With the current plug-in set: **completed in 222 s** (3,311 files); 8 findings after the mapping fixes below |
| FACT | Alpine 3.15 rootfs | with the current plug-in set: completed in 21 s; results from 8 plug-ins (15 findings after the corrected mapping) |

Opt-in real integration tests (`DFA_REAL_TOOLS=1 pytest tests/test_real_tools.py`) cover FwAnalyzer
(Alpine and Debian with the permission image, PX4 CROMFS), cwe_checker (ARM ELF, bare-metal), Ghidra
(bare-metal) and FACT (PX4 CAN bootloader, files extracted from PX4's CROMFS); all eight pass against
the real tools. Mock-based tests in `tests/test_adapters.py` remain for unit coverage of
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
* **Permission image:** extraction never applies setuid bits or owners, so a `dirfs` run cannot check
  permissions. For tar, ext, SquashFS and Unix-made zip root filesystems the sandbox therefore writes a
  cpio (newc) archive whose headers carry the original modes, owners, empty directories and symlinks from
  the archive metadata (`<root>.modes.cpio`); FwAnalyzer reads it in `cpiofs` image mode. SquashFS
  metadata comes from `unsquashfs -lln`, because `unsquashfs` run unprivileged (as in the sandbox) drops
  setuid/setgid bits and owners from the files it writes. FwAnalyzer's cpio backend needs a
  root `.` entry and cannot parse names containing whitespace (such entries are left out and counted).
* **Verified behaviour:** SquashFS image mode preserves setuid/world-writable bits; `Match = true`
  reports *matching* lines; ext2/3/4 image mode panics with stock e2tools (upstream needs a patched
  fork), so ext images use the permission image instead; FwAnalyzer omits empty
  `offenders`/`informational` keys from its JSON report; its `Suid` check reports setuid **and**
  setgid entries as "File is SUID" - the adapter names the real bit from the archive metadata.
* **Limitation:** other directory-mode runs (zips without Unix modes, ROMFS, NuttX) have no permission
  data; the built-in scanner checks setuid/world-writable bits from archive metadata.

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
* **Cortex-M ELF files** (statically linked `ET_EXEC` for `EM_ARM` with Cortex-M build attributes, e.g.
  the unstripped PX4 ELF) make cwe_checker 0.9.0 panic. The sandbox lays out their `PT_LOAD` segments by
  physical address into a flash image (0xFF-filled gaps, ≤ 64 MiB) and writes the ELF's function
  symbols next to it; cwe_checker analyses the image bare-metal with the ELF's load address, and every
  reported address is shown with its function, demangled on the sandbox side with binutils' `c++filt`
  (`0x8079b38 (MissionBlock::get_absolute_altitude_for_item)`; 5,279 of the FMUv2 ELF's 6,934 function
  symbols are C++).
  Ghidra analyses the ELF itself, so symbols and DWARF are used there.
* **`.px4` + `.elf` of the same build** (e.g. a PX4 build directory uploaded as one archive): the image
  decoded from the `.px4` is byte-identical to the one derived from the ELF (same SHA-256 and load
  address), so it is linked to the ELF's symbols, and identical binaries are analysed once - for the
  official FMUv2 pair, cwe_checker runs 3 analyses instead of 6 and Ghidra 3 instead of 5.
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
* **Timeouts and cancellation:** if FACT does not finish within `DFA_FACT_TIMEOUT_S`, or the analysis is
  cancelled in FACT (`recently_canceled_analyses`), the tool run says so (`timeout` / `failed`) and
  keeps whatever plug-in results FACT had produced by then, labelled as partial.
* **Behaviour notes:** FACT's uWSGI closes idle keep-alive connections, so the client uses a fresh
  connection per request and repeats an upload once after a dropped connection (FACT derives the
  UID from the content, so this is idempotent). `.px4` containers, raw MCU images and NuttX CROMFS
  are not unpackable by FACT; the adapter also submits the decoded images and a tar of the files it
  extracted from CROMFS, and says when no plug-in produced results.
* **Stored results:** FACT keeps the results of earlier analyses of identical files (UIDs are content
  hashes) and returns them in the summary, also for plug-ins not requested now. Only the requested
  plug-ins are reported; the tool run lists the ignored ones. (Seen on Debian: cwe_checker results
  from an earlier run that had requested it.)
* **File count:** `number_of_included_files` counts direct children only (1 for a `.tar.gz`); the
  adapter reports `total_files_in_firmware`.
* **Locations:** summaries only carry FACT object IDs; for crypto material and weak exploit
  mitigations the adapter looks up each object's path (`/rest/file_object/<uid>`, bounded), so findings
  name files (on Debian: PIE disabled on `/sbin/ldconfig`, RUNPATH set on the `gconv` modules).
* **Plug-in selection** (`DFA_FACT_PLUGINS`): crypto material, users/passwords, software
  components, CVE lookup, known vulnerabilities, exploit mitigations, ELF analysis. FACT's own
  cwe_checker plug-in is **not** requested by default: in a real run it analysed every ELF of a
  Debian root filesystem one by one (hundreds of binaries, several minutes each), so FACT did not
  finish within the adapter's one-hour timeout. cwe_checker already runs directly on a bounded
  selection of binaries.
* **Result mapping, checked against real output** (Alpine 3.15 root filesystem, FACT finished in 21 s
  with results from eight plug-ins):
  * `users_and_passwords` summaries list every account line (`root:unix`), including shadowed (`x`)
    and locked (`*`, `!`) accounts. The adapter fetches the per-file results and reports only cracked
    passwords (high), stored password hashes (medium) and empty password fields; on Alpine that is
    none (the first mapping had reported 25 "credentials").
  * `crypto_material`: private keys are findings; certificates and public keys are info. The adapter
    looks up where each object is: on Debian both "private keys" FACT reported are GnuTLS's built-in
    self-test keys in `libgnutls.so.30.29.1`, so key material found only inside cryptographic
    libraries is reported as info, not as a leaked key (the built-in secrets scanner does the same).
  * `exploit_mitigations`: only weak states (NX/canary/PIE/RELRO disabled, RPATH/RUNPATH set) are
    reported; "PIE/DSO present", stripped symbols, CLANGCFI/SAFESTACK are not weaknesses.
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
  ESP-IDF, FreeRTOS kernel, Zephyr) **and** to the affected-version ranges published with each CVE
  (OSV's `extracted_events`: the CVE's affected field, NVD CPE ranges, CPE strings or the description;
  each match names its range and source). The ranges matter because OSV's tag lists only contain tags
  on the main branch: releases tagged on release branches - NuttX `nuttx-11.0.0`, used by PX4 - were
  never matched. On the official PX4 builds this added 5 NuttX 11.0.0 CVEs and raised PX4 matches from
  1/0/1 to 19/15/7 for v1.15.0/v1.16.2/v1.17.0. Always `unverified`: vendor backports, and whether the
  affected code (a driver, a host tool, an example) is built into the firmware, are invisible.
  Components already covered by distro package data are not matched twice.
* **Ownership:** findings in files owned by an installed package name that package (dpkg/opkg file
  lists, apk installed database).
* **SBOM / exchange:** CycloneDX 1.5 (`/api/scans/{id}/sbom.cdx.json`) with purls and CPEs; SARIF 2.1.0
  (`/api/scans/{id}/report.sarif`).

## Built-in analyzers (always available)

Run inside the sandbox for every scan: format detection, safe recursive extraction and carving,
platform identification (PX4, ArduPilot, Betaflight, INAV, Espressif, DJI, Parrot, Linux companion),
architecture detection, secrets, insecure configuration, PX4/ArduPilot parameter and MAVLink exposure
checks, ELF hardening, component version strings and package inventories.
