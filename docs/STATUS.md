# Capability status

What works, what partly works and what is unverified, with the evidence behind each statement.
"Real input" means official public builds (PX4 v1.17.0, ArduPilot bootloaders), root filesystems
exported from official Debian/Alpine images, or esptool's published ESP images — never synthetic
data. Numbers come from actual runs in the development environment (2026-11-04/05).

## Fully working (verified with real inputs and covered by tests)

| Capability | Evidence |
|---|---|
| Upload → isolated analysis → report, end to end | Real PX4 FMUv5 `.px4` scan through the broker: built-in scanners, OSV, FwAnalyzer, cwe_checker, Ghidra and FACT all completed (8 findings, 31 min). ArduPilot CubeOrange bootloader and PX4 CAN bootloader: all applicable engines completed. |
| Docker isolation without Docker access in API/worker | Broker is the only Docker client; verified with an unprivileged (uid 10002) worker and a containerised broker (no network, read-only, minimal capabilities). Worker cannot rename scan directories or create links in the work root. |
| Container hardening and limits | `--network none`, read-only rootfs, `cap-drop ALL`, `no-new-privileges`, memory/CPU/PID/fsize limits, timeouts, per-scan disk cap, non-root UIDs (`tests/test_sandbox.py`, real Docker runs). |
| Extraction safety | Traversal, links, devices, bombs, nesting, ext duplicate-entry attack, CROMFS loops (`tests/test_extract_security.py`). |
| PX4 identification and extraction | FMUv2/v5/v6X `.px4`, CAN bootloader, unstripped ELF: platform, version 1.17.0, board ID, Cortex-M architecture, flash base; NuttX CROMFS `/etc` extracted (fixed for FMUv2: peer offset == `cv_fsize`). |
| ArduPilot bootloader identification | Official AP_Bootloader builds (fmuv3, Matek H743, Pixhawk 6X, CubeOrange `.bin`/`.hex`) identified as ArduPilot / AP_Bootloader. |
| cwe_checker | ARM and AArch64 ELF (Debian/Alpine binaries, CWE-676 on `strcpy` user), bare-metal Cortex-M (PX4 image/IO/bootloader, ArduPilot bootloader); results always `unverified`. |
| Ghidra headless layer | Function recovery on ELF (2,500–2,660 functions for perl/libc/bash) and raw Cortex-M images seeded from the vector table (PX4 8,258 functions; ArduPilot bootloader 331). |
| FwAnalyzer | Debian 11 / Alpine 3.15 root filesystems (`dirfs`), PX4 NuttX `/etc` with drone rules (independently matched the `CBRK_SUPPLY_CHK` overrides the built-in scanner found). |
| FACT integration (REST) | Real FACT_core instance: upload, status polling, result retrieval, per-file details. Found and fixed on real output: stale keep-alive resets, per-file cwe_checker slowness, re-submissions misread from earlier runs, and plug-in summaries over-reported as credentials/weaknesses. Alpine rootfs: completed in 21 s. |
| Package inventory and backport-aware matching | Debian 11 (96 packages) and Alpine 3.15 (14) parsed; distro advisories matched against exact installed versions (e.g. `libssl1.1 1.1.1k-1` → DLA-3942-1, fixed in `1.1.1n-0+deb11u6`). |
| File ownership → findings | 3,033 Debian files mapped to their packages; binary findings name the owning package. |
| Architecture detection for raw code | ARM, Thumb-2, AArch64, MIPS, x86-64 verified on real binaries; random/compressed data never classified. |
| ESP32/ESP8266 | Real esptool images: chip, checksum, SHA-256, ESP-IDF app descriptor; flash layouts with partition tables. |
| Reports | PDF (components, vulnerable packages, Ghidra summary), JSON, SARIF 2.1.0, CycloneDX 1.5 SBOM with purls/CPEs. |
| Authentication and authorisation | Users/roles, scrypt, hashed session and API tokens, CSRF header, login throttling, per-user visibility, upload rate/size/disk limits (`tests/test_auth.py`, `tests/test_api.py`). |
| Regression suite | 17 pinned real samples with committed signatures (`tests/test_regression_real.py`); CI job fetches the samples. |

## Partially working

| Capability | Limitation |
|---|---|
| cwe_checker on PX4 debug ELF | cwe_checker 0.9.0 panics on the 47 MB unstripped PX4 ELF (upstream issue); reported verbatim. Bare-metal mode is experimental upstream; a 2 MB image takes ~20 minutes. |
| FACT on MCU firmware | FACT cannot unpack `.px4` containers or raw MCU images; no FACT plug-in produced results for them (reported as such). |
| FACT on full root filesystems | Completes only within the timeout when FACT's per-file cwe_checker plug-in is off (now the default). A large Debian image may still exceed the one-hour default; partial results are kept. |
| FwAnalyzer | Permission checks unavailable in `dirfs` mode (extraction normalises modes); ext image mode panics with stock e2tools. The built-in scanner checks setuid/world-writable from archive metadata. |
| Upstream (non-distro) component matching | Version strings and release tags only (OSV GIT data); vendor backports invisible, so always `unverified`. |
| Ghidra risky-call findings on MCU images | Library calls are recognised by name, so stripped raw images yield function statistics but no call-site findings (the report says so). |
| DJI / Parrot | Headers parsed from public community documentation; DJI encrypted modules are reported, never decrypted; no real vendor samples used. |
| Additional formats: LZ4, Zstandard, lzop, CramFS, EROFS, Android sparse, UBI/UBIFS, JFFS2, SquashFS, ext2/3/4, FAT | Extraction is verified with images produced by the reference tools (`lz4`, `zstd`, `lzop`, `mkfs.cramfs`, `mkfs.erofs`, `img2simg`, `mkfs.ubifs`/`ubinize`, `mkfs.jffs2`, `mksquashfs`, `mkfs.ext4`); no real drone firmware in these formats was available. UBI/UBIFS, JFFS2 and EROFS are only unpacked inside the sandbox container. |
| Upload-file mount race | A compromised API could swap `uploads/<id>.bin` for another host file just before a container starts (read-only, non-root, no capabilities). Scan directories are protected. |

## Unverified

| Capability | Why |
|---|---|
| ArduPilot vehicle firmware (`.apj`, app descriptor, vehicle/version strings) | Only synthetic samples: `firmware.ardupilot.org` was unreachable from the development environment and building ArduPilot from source there was not permitted. |
| gVisor (`DFA_SANDBOX_RUNTIME=runsc`) | Configuration support exists; installing runsc in the development environment was not permitted. |
| Rootless Docker / Podman for the broker | Documented (`docs/SECURITY.md`), not tested. |
| Compose images built from `docker/app.Dockerfile` | The broker/app topology was verified with equivalent locally built images (proxy CA injected); the published Dockerfiles themselves were not built here. |
| New CI job `real-samples` | Defined; CI only runs on pull requests and no PR has been opened for this work yet. |
