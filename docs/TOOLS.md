# External analysis tools: research notes and integration status

The three tools named in the requirements are **not interchangeable**. Before
writing adapters, each project's documentation/source was reviewed and, where
the environment allowed, the tool was run against synthetic fixtures. Each
adapter decides per scan whether the tool *applies* to the uploaded firmware,
and every scan records one of `completed | failed | skipped (not applicable) |
unavailable | timeout` per tool.

| | FwAnalyzer | cwe_checker | FACT |
|---|---|---|---|
| Project | [cruise-automation/fwanalyzer](https://github.com/cruise-automation/fwanalyzer) | [fkie-cad/cwe_checker](https://github.com/fkie-cad/cwe_checker) | [fkie-cad/FACT_core](https://github.com/fkie-cad/FACT_core) |
| What it is | Go CLI, rule-based checks of a Linux filesystem | Rust + Ghidra static analysis of binaries for CWE patterns | Full platform (web UI, backend, DB, plugin containers) |
| Input | ext2/3/4, SquashFS, UBIFS, VFAT, cpio image, or a directory (`dirfs`) | One binary per run. ELF (x86, x86-64, ARM, AArch64, MIPS, PPC; anything Ghidra disassembles). Bare-metal only with `--bare-metal-config` (experimental upstream) | Any firmware; FACT unpacks it itself |
| Output | JSON: `offenders`, `informational`, `data` | `--json --quiet`: JSON array of `{name, version, addresses, tids, symbols, other, description}` | REST: `GET /rest/firmware/<uid>?summary=true` → per-plugin `summary` |
| Install | `go install …/cmd/fwanalyzer`; needs e2tools, squashfs-tools, mtools, ubi_reader, cpio | Docker image `ghcr.io/fkie-cad/cwe_checker` (x86-64 only prebuilt) or Rust ≥1.82 + Ghidra ≥10.2 | Installer for Debian/Ubuntu; min 4 cores/8 GB RAM/10 GB disk; Docker variant unmaintained |
| Applies to PX4/ArduPilot flight-controller binaries? | **No** (not a Linux filesystem) | Only via experimental bare-metal mode (needs memory map) | Partially (FACT can unpack/identify, most plugins target Linux userland) |
| Applies to companion-computer images (Raspberry Pi, Jetson…)? | Yes | Yes (ELF userland) | Yes |
| Maintenance | No longer actively developed (last module version 2023-10) | Active | Active |

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

### cwe_checker — adapter complete, tool not runnable in the development sandbox
* Uses a local `cwe_checker` binary if present, otherwise the Docker image
  (`DFA_CWE_CHECKER_IMAGE`) run with `--network none`, memory/PID limits,
  `--cap-drop ALL`, firmware mounted read-only.
* Selects up to `DFA_CWE_CHECKER_MAX_BINARIES` ELF binaries of supported
  architectures, prioritising network-facing/drone-related names
  (mavlink, httpd, sshd, telemetry, …) and skipping kernel modules/BusyBox.
* Raw Cortex-M images (PX4/ArduPilot) are only analysed when
  `DFA_CWE_CHECKER_BARE_METAL=true`; the adapter then writes a bare-metal
  config (`processor_id ARM:LE:32:Cortex`, detected flash base, SRAM
  0x20000000). This mode is experimental upstream and was not validated here.
* Warnings are grouped per (binary, CWE) and always classified `unverified`
  (upstream documents expected false positives/negatives).
* **Validation status:** pulling `ghcr.io/fkie-cad/cwe_checker` was blocked by
  the network policy of the environment this MVP was built in, so the adapter
  was validated against output that follows the upstream `CweWarning` schema
  (`tests/test_adapters.py`). In that environment the tool is correctly
  reported as `unavailable` with the exact `docker pull` command to fix it.

### FACT — REST adapter, not validated against a live instance
* FACT is a multi-service platform with heavy requirements, so it is
  integrated as an **external service** (`DFA_FACT_URL`, optional
  `DFA_FACT_API_KEY`). Without it the tool is reported `unavailable` ("Not
  configured").
* Upload: `PUT /rest/firmware` with base64 `binary` and the required metadata
  fields (`device_name`, `device_part`, `device_class`, `file_name`,
  `version`, `vendor`, `release_date`, `tags`, `requested_analysis_systems`).
* Completion: polls `GET /rest/status` until the UID leaves
  `system_status.backend.analysis.current_analyses`, then reads
  `GET /rest/firmware/<uid>?summary=true`.
* Normalisation maps the plugins `crypto_material`, `users_and_passwords`,
  `cve_lookup`, `known_vulnerabilities`, `cwe_checker` and
  `exploit_mitigations` (missing mitigations only) to findings;
  version/signature-based plugins are `unverified`.
* **Validation status:** tested with a mock FACT server that follows the
  upstream REST resource definitions (`src/web_interface/rest/rest_firmware.py`).
  It has *not* been exercised against a real FACT deployment; field names in
  the status endpoint are the most likely point of drift.

## Built-in analyzers (always available)

Run inside the sandbox for every scan: content-based format detection,
recursive safe extraction (with carving of embedded ROMFS/gzip/SquashFS/uImage/
cpio/ELF), PX4/ArduPilot identification, secrets, insecure configuration,
drone parameter / MAVLink exposure checks, ELF hardening, and component
version checks against an offline knowledge base
(`backend/dfa/core/data/component_kb.json`, extendable via `DFA_COMPONENT_KB`).
