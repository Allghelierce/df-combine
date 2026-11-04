"""cwe_checker adapter (https://github.com/fkie-cad/cwe_checker).

Verified in this project's environment with cwe_checker 0.9.0 (``fkiecad/cwe_checker`` on
Docker Hub, which bundles Ghidra 11.2.1):
* Input: one binary per run. ELF executables/libraries of the architectures Ghidra can lift
  (x86, x86-64, ARM, AArch64, MIPS, PPC, RISC-V...). Raw firmware only with
  ``--bare-metal-config`` (processor id, flash base, RAM base/size); upstream marks bare-metal
  support as experimental.
* Output: ``--json --quiet`` prints a JSON array of CweWarning objects
  ``{name, version, addresses, tids, symbols, other, description}`` on stdout.
* Results are static-analysis warnings with known false positives/negatives; every finding is
  classified ``unverified``.
"""
from __future__ import annotations

import json
import re
import shutil
from collections import defaultdict

from ..containers import JobError, JobRejected, get_runner
from ..core.findings import Classification as C
from ..core.findings import Confidence as K
from ..core.findings import Evidence, Finding
from ..core.findings import Severity as S
from .base import AdapterContext, AdapterResult, ToolAdapter, run_cmd

SUPPORTED_ELF_ARCH = {"EM_ARM", "EM_AARCH64", "EM_X86_64", "EM_386", "EM_MIPS", "EM_PPC", "EM_PPC64", "EM_RISCV"}
CWE_SEVERITY = {
    "CWE78": S.high, "CWE119": S.medium, "CWE125": S.medium, "CWE787": S.medium, "CWE134": S.medium,
    "CWE190": S.low, "CWE215": S.info, "CWE243": S.low, "CWE252": S.low, "CWE332": S.low, "CWE337": S.low,
    "CWE367": S.low, "CWE416": S.medium, "CWE415": S.medium, "CWE426": S.low, "CWE467": S.low, "CWE476": S.low,
    "CWE560": S.low, "CWE676": S.low, "CWE782": S.low, "CWE789": S.low,
}
CWE_TITLES = {
    "CWE78": "OS command injection", "CWE119": "Buffer overflow", "CWE125": "Out-of-bounds read",
    "CWE787": "Out-of-bounds write", "CWE134": "Externally-controlled format string",
    "CWE190": "Integer overflow", "CWE215": "Debug information exposure", "CWE243": "chroot without chdir",
    "CWE252": "Unchecked return value", "CWE332": "Insufficient PRNG entropy", "CWE337": "Predictable PRNG seed",
    "CWE367": "TOCTOU race condition", "CWE416": "Use after free", "CWE415": "Double free",
    "CWE426": "Untrusted search path", "CWE467": "sizeof() on pointer type", "CWE476": "NULL pointer dereference",
    "CWE560": "umask() with chmod-style argument", "CWE676": "Use of potentially dangerous function",
    "CWE782": "Exposed IOCTL without access control", "CWE789": "Excessive memory allocation",
}
PRIORITY_NAMES = re.compile(r"(mavlink|router|httpd|lighttpd|nginx|sshd|dropbear|telnetd|ftpd|upnp|rtsp|"
                            r"video|stream|camera|gimbal|flight|drone|uav|gcs|telem|update|ota|cloud|api|px4|"
                            r"ardu|d$)", re.I)


def bare_metal_config(art: dict) -> dict | None:
    """cwe_checker bare-metal configuration for a raw Cortex-M artifact (from the analysis manifest)."""
    d = art.get("details", {})
    base = d.get("flash_base") or d.get("load_address")
    if not base:
        return None
    sp = int(d.get("initial_sp", "0x20020000"), 16)
    ram_base = 0x2000_0000 if sp < 0x2400_0000 else 0x2400_0000
    ram_size = max(0x20000, ((sp - ram_base + 0xFFFF) // 0x10000) * 0x10000)
    return {"processor_id": "ARM:LE:32:Cortex", "flash_base_address": base,
            "ram_base_address": hex(ram_base), "ram_size": hex(ram_size)}


class CweCheckerAdapter(ToolAdapter):
    name = "cwe_checker"
    display_name = "cwe_checker (FKIE)"
    homepage = "https://github.com/fkie-cad/cwe_checker"
    inputs = ("ELF binaries (x86/ARM/AArch64/MIPS/PPC/RISC-V); raw Cortex-M firmware via bare-metal mode "
              "(experimental upstream)")

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
        runner = get_runner(self.settings)
        caps = runner.capabilities()
        img = self.settings.cwe_checker_image
        if not caps.get("docker") and not caps.get("broker"):
            return self._status(False, "Neither a local cwe_checker nor Docker/the sandbox broker is available. "
                                       f"Pull '{img}' (Docker Hub) or install cwe_checker + Ghidra.")
        if not caps.get("images", {}).get(img):
            return self._status(False, f"Docker image '{img}' is not present. Run 'docker pull {img}' "
                                       "(Docker Hub mirror of ghcr.io/fkie-cad/cwe_checker).", mode=runner.kind)
        return self._status(True, f"Docker image {img} via {runner.kind}", mode=runner.kind)

    def plan(self, ctx: AdapterContext):
        arts = ctx.manifest.get("extraction", {}).get("artifacts", [])
        cands = []
        for a in arts:
            elf = a.get("elf")
            if a.get("format") == "elf" and elf:
                if elf.get("machine") not in SUPPORTED_ELF_ARCH or elf.get("is_kernel_module"):
                    continue
                score = 0
                if a.get("category") == "executable":
                    score += 10
                if PRIORITY_NAMES.search(a["name"].rsplit("/", 1)[-1]):
                    score += 5
                if "busybox" in a["name"]:
                    score -= 20
                if a.get("category") == "firmware_image":
                    score += 8
                cands.append((score, a["size"], {"artifact": a, "bare_metal": None}))
            elif a.get("format") == "cortexm_raw" and self.settings.cwe_checker_bare_metal:
                cfg = bare_metal_config(a)
                if cfg:
                    # main application images first (largest), bootloaders/co-processor images after
                    cands.append((6, a["size"], {"artifact": a, "bare_metal": cfg}))
        if not cands:
            has_raw = any(a.get("format") == "cortexm_raw" for a in arts)
            if has_raw and not self.settings.cwe_checker_bare_metal:
                return [], ("no ELF binaries; the firmware is a raw Cortex-M image and bare-metal mode is disabled "
                            "(DFA_CWE_CHECKER_BARE_METAL=true enables it)")
            return [], "no ELF binaries for a supported architecture and no raw Cortex-M image with a known load address"
        cands.sort(key=lambda c: (-c[0], -c[1]))
        n = self.settings.cwe_checker_max_binaries
        return [c[2] for c in cands[:n]], f"{len(cands)} candidates, analysing top {n}"

    def run(self, ctx: AdapterContext, targets: list) -> AdapterResult:
        out_dir = ctx.tool_dir(self.name)
        findings: list[Finding] = []
        per_target = []
        failures = 0
        local = self._local()
        runner = None if local else get_runner(self.settings)
        for i, t in enumerate(targets):
            a = t["artifact"]
            ctx.log(f"cwe_checker: analysing {a['display_path']} ({i + 1}/{len(targets)})"
                    + (" in bare-metal mode" if t["bare_metal"] else ""))
            cfg_rel = None
            if t["bare_metal"]:
                cfg_path = out_dir / f"bare_metal_{i}.json"
                cfg_path.write_text(json.dumps(t["bare_metal"]))
                cfg_rel = cfg_path
            try:
                if local:
                    cmd = [local, str(ctx.artifact_path(a)), "--json", "--quiet"]
                    if cfg_rel:
                        cmd += ["--bare-metal-config", str(cfg_rel)]
                    rc, stdout, stderr, dur = run_cmd(cmd, timeout=self.settings.cwe_checker_timeout_s)
                    killed = None
                else:
                    params = {"target": ctx.container_path(a)}
                    if cfg_rel:
                        params["bare_metal_config"] = ctx.container_path_of(cfg_rel)
                    res = runner.run("cwe_checker", ctx.scan_id, params)
                    rc, stdout, stderr, dur, killed = (res.exit_code, res.stdout, res.stderr, res.duration_s,
                                                       res.killed_reason)
            except (JobError, JobRejected, OSError) as exc:
                failures += 1
                per_target.append({"binary": a["display_path"], "status": "failed", "error": str(exc)[:300]})
                continue
            except Exception as exc:  # noqa: BLE001 - e.g. TimeoutExpired in local mode
                failures += 1
                per_target.append({"binary": a["display_path"], "status": "failed", "error": str(exc)[:300]})
                continue
            (out_dir / f"result_{i}.json").write_text(stdout)
            (out_dir / f"stderr_{i}.log").write_text(stderr[-20000:])
            if killed or rc != 0:
                failures += 1
                per_target.append({"binary": a["display_path"], "status": "timeout" if killed else "failed",
                                   "exit_code": rc, "error": killed or _failure_reason(stdout, stderr, rc)})
                continue
            try:
                warnings = parse_output(stdout)
            except ValueError as exc:
                failures += 1
                per_target.append({"binary": a["display_path"], "status": "failed", "error": str(exc)})
                continue
            fs = normalize(warnings, a["display_path"], bare_metal=bool(t["bare_metal"]))
            findings += fs
            per_target.append({"binary": a["display_path"], "status": "completed", "warnings": len(warnings),
                               "duration_s": dur, "mode": "bare-metal" if t["bare_metal"] else "elf",
                               "bare_metal_config": t["bare_metal"]})
        ok = len(targets) - failures
        status = "completed" if ok else "failed"
        msg = f"analysed {ok}/{len(targets)} binaries, {len(findings)} grouped findings"
        if failures:
            msg += f" ({failures} failed/timed out: " + "; ".join(
                f"{p['binary'].rsplit(' > ', 1)[-1]}: {p.get('error', '')[:120]}" for p in per_target
                if p["status"] != "completed") + ")"
        return AdapterResult(status, msg, findings, str(out_dir), {"targets": per_target})


def _failure_reason(stdout: str, stderr: str, rc: int | None) -> str:
    """Most informative line of a failed run (Rust panics of cwe_checker itself are reported verbatim)."""
    text = stderr + "\n" + stdout
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if "panicked at" in ln:
            nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
            return f"cwe_checker crashed (exit {rc}): {ln.strip()} {nxt}"[:400]
    for ln in reversed(lines):
        if ln.strip():
            return f"exit {rc}: {ln.strip()}"[:400]
    return f"exit {rc}, no output"


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


def _addresses(w: dict) -> list[str]:
    """Hex addresses of a warning.

    cwe_checker 0.9.0 prints ``addresses`` as *decimal* strings (verified: '4198853' == 0x4011c5 for a
    call to strcpy) while ``tids`` carry the hex form ('instr_0x004011c5_2'); prefer the tids.
    """
    out = []
    for tid in w.get("tids", []):
        m = re.search(r"0x([0-9a-fA-F]+)", str(tid))
        if m:
            out.append(f"0x{int(m.group(1), 16):x}")
    if not out:
        for a in w.get("addresses", []):
            a = str(a)
            out.append(f"0x{int(a):x}" if a.isdigit() else a)
    return list(dict.fromkeys(out))


def normalize(warnings: list[dict], binary: str, bare_metal: bool = False) -> list[Finding]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for w in warnings:
        grouped[str(w.get("name", "CWE?"))].append(w)
    out = []
    for cwe_name, ws in grouped.items():
        num = cwe_name.replace("CWE", "")
        title = CWE_TITLES.get(cwe_name, cwe_name)
        ev = []
        for w in ws[:25]:
            addrs = ",".join(_addresses(w)[:3])
            syms = ",".join(w.get("symbols", [])[:3])
            desc = str(w.get("description", ""))[:240]
            ev.append(Evidence("address", desc, f"{addrs}{' in ' + syms if syms else ''}"))
        out.append(Finding(
            title=f"[cwe_checker] {cwe_name}: {title} ({len(ws)} warning{'s' if len(ws) != 1 else ''})",
            description=("cwe_checker's static analysis (Ghidra P-Code + abstract interpretation) reported potential "
                         f"instances of CWE-{num} ({title}). These are analysis warnings with known false "
                         "positives; each location requires manual review before it can be called a vulnerability."
                         + (" Analysed in experimental bare-metal mode (raw firmware, no symbols)." if bare_metal
                            else "")),
            severity=CWE_SEVERITY.get(cwe_name, S.low), classification=C.unverified, confidence=K.low,
            source_tool="cwe_checker", rule_id=cwe_name, affected_component=binary,
            remediation=f"Review the reported addresses (e.g. with the cwe_checker Ghidra plugin) and fix confirmed "
                        f"instances of CWE-{num}.",
            evidence=ev, cwe=f"CWE-{num}" if num.isdigit() else None,
            references=[f"https://cwe.mitre.org/data/definitions/{num}.html"] if num.isdigit() else [],
            tags=["static-analysis"] + (["bare-metal"] if bare_metal else [])))
    return out
