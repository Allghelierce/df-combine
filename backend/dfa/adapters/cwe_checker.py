"""cwe_checker adapter (https://github.com/fkie-cad/cwe_checker).

Facts established from the upstream project:
* Input: a single binary. Primary target is ELF (x86, x86-64, ARM, AArch64,
  MIPS, PPC - anything Ghidra can disassemble). Bare-metal images require a
  ``--bare-metal-config`` JSON (processor id, flash base, RAM base/size) and
  support is marked *experimental* upstream.
* Requires Ghidra (headless) - easiest via the Docker image
  ``ghcr.io/fkie-cad/cwe_checker`` (``:stable`` x86-64 only; ``:latest`` also arm64).
* Output: ``--json`` (with ``--quiet``) prints a JSON array of CweWarning
  objects: {name, version, addresses, tids, symbols, other, description}.
* Results are static-analysis warnings with expected false positives and
  negatives, hence every finding is classified ``unverified``.
"""
from __future__ import annotations

import contextlib
import json
import re
import shutil
import uuid
from collections import defaultdict
from pathlib import Path

from ..core.findings import Classification as C
from ..core.findings import Confidence as K
from ..core.findings import Evidence, Finding
from ..core.findings import Severity as S
from ..sandbox import _host_path, docker_available, docker_image_present
from .base import AdapterContext, AdapterResult, ToolAdapter, run_cmd

SUPPORTED_ELF_ARCH = {"EM_ARM", "EM_AARCH64", "EM_X86_64", "EM_386", "EM_MIPS", "EM_PPC", "EM_PPC64", "EM_RISCV"}
CWE_SEVERITY = {
    "CWE78": S.high, "CWE119": S.medium, "CWE125": S.medium, "CWE787": S.medium, "CWE134": S.medium,
    "CWE190": S.low, "CWE215": S.info, "CWE243": S.low, "CWE252": S.low, "CWE332": S.low, "CWE337": S.low, "CWE367": S.low,
    "CWE416": S.medium, "CWE415": S.medium, "CWE426": S.low, "CWE467": S.low, "CWE476": S.low,
    "CWE560": S.low, "CWE676": S.low, "CWE782": S.low, "CWE789": S.low,
}
CWE_TITLES = {
    "CWE78": "OS command injection", "CWE119": "Buffer overflow", "CWE125": "Out-of-bounds read",
    "CWE787": "Out-of-bounds write", "CWE134": "Externally-controlled format string",
    "CWE190": "Integer overflow", "CWE215": "Debug information exposure", "CWE243": "chroot without chdir",
    "CWE252": "Unchecked return value",
    "CWE332": "Insufficient PRNG entropy", "CWE337": "Predictable PRNG seed", "CWE367": "TOCTOU race condition",
    "CWE416": "Use after free", "CWE415": "Double free", "CWE426": "Untrusted search path",
    "CWE467": "sizeof() on pointer type", "CWE476": "NULL pointer dereference",
    "CWE560": "umask() with chmod-style argument", "CWE676": "Use of potentially dangerous function",
    "CWE782": "Exposed IOCTL without access control", "CWE789": "Excessive memory allocation",
}
PRIORITY_NAMES = re.compile(r"(mavlink|router|httpd|lighttpd|nginx|sshd|dropbear|telnetd|ftpd|upnp|rtsp|"
                            r"video|stream|camera|gimbal|flight|drone|uav|gcs|telem|update|ota|cloud|api|d$)", re.I)


class CweCheckerAdapter(ToolAdapter):
    name = "cwe_checker"
    display_name = "cwe_checker (FKIE)"
    homepage = "https://github.com/fkie-cad/cwe_checker"
    inputs = "Single ELF binaries (x86/ARM/MIPS/PPC); bare-metal images only with a memory-map config (experimental)"

    def enabled(self) -> bool:
        return self.settings.cwe_checker_enabled

    def _local(self) -> str | None:
        return self.settings.cwe_checker_bin or shutil.which("cwe_checker")

    def status(self):
        local = self._local()
        if local:
            rc, out, err, _ = run_cmd([local, "--version"], timeout=60)
            return self._status(rc == 0, f"local binary {local}" if rc == 0 else f"{local} --version failed: {err[:200]}",
                                mode="local", version=(out or err).strip()[:80] or None)
        if not docker_available():
            return self._status(False, "cwe_checker is not installed locally and Docker is not available. Install "
                                       "Ghidra + cwe_checker or pull the Docker image "
                                       f"'{self.settings.cwe_checker_image}'.")
        if not docker_image_present(self.settings.cwe_checker_image):
            return self._status(False, f"Docker image '{self.settings.cwe_checker_image}' is not present. Run "
                                       f"'docker pull {self.settings.cwe_checker_image}'.", mode="docker")
        return self._status(True, f"Docker image {self.settings.cwe_checker_image}", mode="docker")

    def plan(self, ctx: AdapterContext):
        arts = ctx.manifest.get("extraction", {}).get("artifacts", [])
        cands = []
        for a in arts:
            elf = a.get("elf")
            if a.get("format") == "elf" and elf:
                if elf.get("machine") not in SUPPORTED_ELF_ARCH or elf.get("is_kernel_module"):
                    continue
                if "busybox" in a["name"]:  # ~9 min and thousands of warnings per run; rarely the target
                    continue
                score = 0
                if a.get("category") == "executable":
                    score += 10
                if PRIORITY_NAMES.search(a["name"].rsplit("/", 1)[-1]):
                    score += 5
                if a.get("category") == "firmware_image":
                    score += 8
                cands.append((score, a["size"], {"artifact": a, "bare_metal": None}))
            elif a.get("format") == "cortexm_raw" and self.settings.cwe_checker_bare_metal:
                load = a.get("details", {}).get("load_address") or a.get("details", {}).get("flash_base_guess") or "0x08000000"
                cands.append((1, a["size"], {"artifact": a, "bare_metal": {
                    "processor_id": "ARM:LE:32:Cortex", "flash_base_address": load,
                    "ram_base_address": "0x20000000", "ram_size": "0x00030000"}}))
        if not cands:
            has_raw = any(a.get("format") == "cortexm_raw" for a in arts)
            if has_raw:
                return [], ("no ELF binaries; the firmware is a raw Cortex-M image. cwe_checker's bare-metal mode "
                            "is experimental and disabled (set DFA_CWE_CHECKER_BARE_METAL=true to try it)")
            return [], "no ELF binaries for a supported architecture were found in the firmware"
        cands.sort(key=lambda c: (-c[0], -c[1]))
        n = self.settings.cwe_checker_max_binaries
        return [c[2] for c in cands[:n]], f"{len(cands)} candidates, analysing top {n}"

    def run(self, ctx: AdapterContext, targets: list) -> AdapterResult:
        out_dir = ctx.tool_dir(self.name)
        findings: list[Finding] = []
        per_target = []
        failures = 0
        st = self.status()
        for i, t in enumerate(targets):
            a = t["artifact"]
            path = ctx.artifact_path(a)
            ctx.log(f"cwe_checker: analysing {a['name']} ({i + 1}/{len(targets)})")
            cfg_path = None
            if t["bare_metal"]:
                cfg_path = out_dir / f"bare_metal_{i}.json"
                cfg_path.write_text(json.dumps(t["bare_metal"]))
            container = f"dfa-cwe-{uuid.uuid4().hex[:12]}" if st.mode == "docker" else None
            cmd = self._command(st.mode, path, cfg_path, container)
            try:
                rc, stdout, stderr, dur = run_cmd(cmd, timeout=self.settings.cwe_checker_timeout_s)
            except Exception as exc:  # noqa: BLE001 - includes TimeoutExpired per binary
                if container:  # killing the docker CLI does not stop the container
                    _remove_container(container)
                failures += 1
                per_target.append({"binary": a["display_path"], "status": "failed", "error": str(exc)[:300]})
                continue
            (out_dir / f"result_{i}.json").write_text(stdout)
            (out_dir / f"stderr_{i}.log").write_text(stderr[-20000:])
            if rc != 0:
                failures += 1
                per_target.append({"binary": a["display_path"], "status": "failed", "exit_code": rc,
                                   "error": stderr.strip()[-400:]})
                continue
            try:
                warnings = parse_output(stdout)
            except ValueError as exc:
                failures += 1
                per_target.append({"binary": a["display_path"], "status": "failed", "error": str(exc)})
                continue
            fs = normalize(warnings, a["display_path"])
            findings += fs
            per_target.append({"binary": a["display_path"], "status": "completed", "warnings": len(warnings),
                               "duration_s": dur})
        status = "completed" if failures == 0 else ("failed" if failures == len(targets) else "completed")
        msg = f"analysed {len(targets) - failures}/{len(targets)} binaries, {len(findings)} grouped findings"
        if failures:
            msg += f" ({failures} failed)"
        return AdapterResult(status, msg, findings, str(out_dir), {"targets": per_target})

    def _command(self, mode: str | None, path: Path, cfg: Path | None, container: str | None = None) -> list[str]:
        if mode == "local":
            cmd = [self._local() or "cwe_checker", str(path), "--json", "--quiet"]
            if cfg:
                cmd += ["--bare-metal-config", str(cfg)]
            return cmd
        cmd = ["docker", "run", "--rm", *(["--name", container] if container else []),
               "--network", "none", "--memory", self.settings.cwe_checker_memory,
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--pids-limit", "512", "-v", f"{_host_path(path, self.settings)}:/input:ro"]
        if cfg:
            cmd += ["-v", f"{_host_path(cfg, self.settings)}:/bare_metal.json:ro"]
        cmd += [self.settings.cwe_checker_image, "/input", "--json", "--quiet"]
        if cfg:
            cmd += ["--bare-metal-config", "/bare_metal.json"]
        return cmd


def _remove_container(name: str) -> None:
    # Best effort: the original failure is what gets reported.
    with contextlib.suppress(Exception):
        run_cmd(["docker", "rm", "-f", name], timeout=60)


def parse_output(stdout: str) -> list[dict]:
    text = stdout.strip()
    if not text:
        return []
    start = text.find("[")
    if start < 0:
        raise ValueError("cwe_checker output contains no JSON array")
    try:
        data = json.loads(text[start:])
    except json.JSONDecodeError as exc:
        raise ValueError(f"could not parse cwe_checker JSON: {exc}") from None
    if not isinstance(data, list):
        raise ValueError("unexpected cwe_checker JSON structure")
    return [w for w in data if isinstance(w, dict) and "name" in w]


def normalize(warnings: list[dict], binary: str) -> list[Finding]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for w in warnings:
        grouped[str(w.get("name", "CWE?"))].append(w)
    out = []
    for cwe_name, ws in grouped.items():
        num = cwe_name.replace("CWE", "")
        title = CWE_TITLES.get(cwe_name, cwe_name)
        ev = []
        for w in ws[:20]:
            addrs = ",".join(w.get("addresses", [])[:3])
            syms = ",".join(w.get("symbols", [])[:3])
            desc = str(w.get("description", ""))[:240]
            ev.append(Evidence("address", desc, f"{addrs}{' ' + syms if syms else ''}"))
        out.append(Finding(
            title=f"[cwe_checker] {cwe_name}: {title} ({len(ws)} warning{'s' if len(ws) != 1 else ''})",
            description=("cwe_checker's static analysis reported potential instances of "
                         f"CWE-{num} ({title}). These are analysis warnings with known false positives; each "
                         "location requires manual review in a disassembler before it can be called a vulnerability."),
            severity=CWE_SEVERITY.get(cwe_name, S.low), classification=C.unverified, confidence=K.low,
            source_tool="cwe_checker", rule_id=cwe_name, affected_component=binary,
            remediation=f"Review the reported addresses (e.g. with the cwe_checker Ghidra plugin) and fix confirmed "
                        f"instances of CWE-{num}.",
            evidence=ev, cwe=f"CWE-{num}" if num.isdigit() else None,
            references=[f"https://cwe.mitre.org/data/definitions/{num}.html"] if num.isdigit() else [],
            tags=["static-analysis"]))
    return out
