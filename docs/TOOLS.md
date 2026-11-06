# External analysis tools: research notes and integration status

The external tools are **not interchangeable**. Before writing adapters, each
project's documentation/source was reviewed and, where
the environment allowed, the tool was run against synthetic fixtures. Each
adapter decides per scan whether the tool *applies* to the uploaded firmware,
and every scan records one of `completed | failed | skipped (not applicable) |
unavailable | timeout` per tool.

| | FwAnalyzer | cwe_checker |
|---|---|---|
| Project | [cruise-automation/fwanalyzer](https://github.com/cruise-automation/fwanalyzer) | [fkie-cad/cwe_checker](https://github.com/fkie-cad/cwe_checker) |
| What it is | Go CLI, rule-based checks of a Linux filesystem | Rust + Ghidra static analysis of binaries for CWE patterns |
| Input | ext2/3/4, SquashFS, UBIFS, VFAT, cpio image, or a directory (`dirfs`) | One binary per run. ELF (x86, x86-64, ARM, AArch64, MIPS, PPC; anything Ghidra disassembles). Bare-metal only with `--bare-metal-config` (experimental upstream) |
| Output | JSON: `offenders`, `informational`, `data` | `--json --quiet`: JSON array of `{name, version, addresses, tids, symbols, other, description}` |
| Install | `go install …/cmd/fwanalyzer`; needs e2tools, squashfs-tools, mtools, ubi_reader, cpio | Docker image `ghcr.io/fkie-cad/cwe_checker` (`:stable` x86-64 only; `:latest` also arm64) or Rust ≥1.82 + Ghidra ≥10.2 |
| Applies to PX4/ArduPilot flight-controller binaries? | **No** (not a Linux filesystem) | Only via experimental bare-metal mode (needs memory map) |
| Applies to companion-computer images (Raspberry Pi, Jetson…)? | Yes | Yes (ELF userland) |
| Maintenance | No longer actively developed (last module version 2023-10) | Active |

## How each one is integrated

### FwAnalyzer — validated by running it
* **Bundled in the sandbox image** (`docker/sandbox.Dockerfile`, pinned
  revision) and executed *inside* the network-less sandbox container, because
  it parses untrusted filesystem images. If the image lacks it, a host binary
  on `PATH` is used and the status says "NOT container-isolated".
* The adapter generates the TOML rule set per scan: `Suid`, `WorldWrite`,
  `BadFiles` (host keys, private keys, `authorized_keys`, shell history,
  telnetd, gdbserver…), plus `FileContent` regexes for `/etc/shadow` empty
  passwords, `PermitEmptyPasswords yes` and telnetd in inittab — only for files
  that exist (FwAnalyzer reports a missing file as an offender).
* Verified behaviour (see `tests/test_adapters.py::test_fwanalyzer_real_run`,
  `tests/test_sandbox.py::test_fwanalyzer_runs_inside_sandbox`):
  * SquashFS image mode works and preserves setuid/world-writable bits.
  * `Match = true` reports lines that *match* the regex (verified empirically).
  * **ext2/3/4 image mode panics with the stock Ubuntu e2tools package**
    (`index out of range` in `extparser.parseFileLine`; upstream documents a
    patched e2tools fork). The adapter detects this, falls back to `dirfs` on
    our safely-extracted tree and records the fallback in the tool-run message.
    In `dirfs` mode permission checks are disabled because extraction
    normalises file modes.
* Not applicable (reported as `skipped`) when no Linux root filesystem was
  found — e.g. PX4/ArduPilot `.px4`/`.apj`/`.bin`/`.hex`.

### cwe_checker — validated against the real tool (Docker, arm64)
* Uses a local `cwe_checker` binary if present, otherwise the Docker image
  (`DFA_CWE_CHECKER_IMAGE`) run with `--network none`, memory/PID limits,
  `--cap-drop ALL`, firmware mounted read-only. Each container is named
  `dfa-cwe-<random>` and removed with `docker rm -f` if the run times out or
  errors (killing the `docker` CLI alone leaves the container running).
* Selects up to `DFA_CWE_CHECKER_MAX_BINARIES` ELF binaries of supported
  architectures, prioritising network-facing/drone-related names
  (mavlink, httpd, sshd, telemetry, …) and skipping kernel modules/BusyBox.
* Raw Cortex-M images (PX4/ArduPilot) are only analysed when
  `DFA_CWE_CHECKER_BARE_METAL=true`; the adapter then writes a bare-metal
  config (`processor_id ARM:LE:32:Cortex`, detected flash base, SRAM
  0x20000000). This mode is experimental upstream and was not validated here.
* Warnings are grouped per (binary, CWE) and always classified `unverified`
  (upstream documents expected false positives/negatives).
* **Validation status:** run end to end with `ghcr.io/fkie-cad/cwe_checker:latest`
  (arm64, Docker Desktop) on three aarch64 musl binaries: `ssl_client` (67 KB,
  25 s, 0 warnings), `scanelf` (130 KB, 49 s, 203 warnings) and BusyBox
  (900 KB, ~9 min, 3853 warnings). The real JSON matched the `CweWarning`
  fields the parser expects; CWE-252, which the tool reports but the adapter
  did not know, was added. `:stable` has no arm64 build, so arm64 hosts must
  set `DFA_CWE_CHECKER_IMAGE` to `:latest`. Without the tool the adapter is
  reported `unavailable` with the `docker pull` command to fix it.

### FACT — removed
[FACT](https://github.com/fkie-cad/FACT_core) was integrated through its REST
API until November 2026 and then removed. It is a separate multi-service
platform that needs its own Debian/Ubuntu host (minimum 4 cores, 8 GB RAM,
10 GB disk; the Docker variant is unmaintained and ARM support is not
documented), and the adapter was only ever tested against a mock server, never
a real FACT deployment. Most of its plugins duplicated checks the app already
runs; CVE matching is handled inside the app instead (see "CVE lookup" below).

### CVE lookup — built in, data from public feeds
Not an external program: `backend/dfa/adapters/cve_lookup.py` queries a local
SQLite database built by `make cve-db` from NVD (fkie-cad mirror of the NVD
JSON 2.0 feeds), CISA KEV and Exploit-DB. It runs in the app/worker process,
outside the sandbox, and reads only the manifest's component list and platform
identification. NVD product names in `backend/dfa/cve/cpe_map.json` were
checked against the 2026-11-06 feed. Without the database the tool is reported
`unavailable` with the command to build it; an unreadable database is reported
`failed`.
* **Feeds:** NVD JSON 2.0 via the daily
  [fkie-cad mirror](https://github.com/fkie-cad/nvd-json-data-feeds) (~400,000
  CVEs), the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  catalog and [Exploit-DB](https://gitlab.com/exploit-database/exploitdb)'s CVE
  cross-references. `make cve-db` downloads about 125 MB and builds a ~400 MB
  database in under a minute; a failed refresh keeps the previous database.
  `python -m dfa.cve info` shows what it holds.
* **Matching:** the components the built-in scanners identified (version
  strings in binaries, plus Debian `dpkg` and OpenWrt `opkg` package lists) and
  the identified flight-controller platform are mapped to NVD products and
  matched against NVD's affected version ranges. CVEs NVD has not analysed yet
  are matched on the ranges the vendor published (shown as "vendor data"). Only
  component names and versions are used; nothing is queried online during a
  scan.
* **Results:** the scan's **Vulnerabilities** tab, the PDF and the JSON report
  (tool run `details`). Findings are grouped: one per component ("openssl
  1.0.1e: 77 known CVEs"), plus one per CVE that is actively exploited (CISA
  KEV) or has a public exploit. Every match is `unverified`. Components with no
  NVD product (ChibiOS, mavlink-router, Betaflight, INAV) are listed as "no CVE
  mapping".

## Built-in analyzers (always available)

Run inside the sandbox for every scan: content-based format detection,
recursive safe extraction (with carving of embedded ROMFS/gzip/SquashFS/uImage/
cpio/ELF), PX4/ArduPilot identification, secrets, insecure configuration,
drone parameter / MAVLink exposure checks, ELF hardening, and component
version checks against an offline knowledge base
(`backend/dfa/core/data/component_kb.json`, extendable via `DFA_COMPONENT_KB`).
When the CVE database is installed, knowledge-base findings whose CVEs it
already reports are dropped so each CVE appears once.
