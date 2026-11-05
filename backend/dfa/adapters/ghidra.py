"""Ghidra headless adapter: function-level static analysis.

Runs Ghidra's ``analyzeHeadless`` (shipped in the fkiecad/cwe_checker image, Ghidra 11.x) with the
project's own scripts in ``dfa/ghidra_scripts``:

* ``DfaCortexMVectors.java`` (pre-script, raw Cortex-M images only) seeds functions from the
  vector table, because raw flash images have no symbols or entry points;
* ``DfaExport.java`` (post-script) exports program facts, the function inventory (size, callers,
  callees), memory blocks and call sites of risky libc functions as JSON.

ELF binaries are imported with Ghidra's ELF loader; raw Cortex-M images are imported with the
binary loader at the flash base estimated by the analysis stage. Findings are limited to what
the data supports: a call to ``gets`` is evidence of an unsafe API in use (``detected``), other
risky calls are review pointers (``suspicious``); nothing claims exploitability.
"""
from __future__ import annotations

import json
from collections import Counter

from ..containers import JobError, JobRejected, get_runner
from ..core.findings import Classification as C
from ..core.findings import Confidence as K
from ..core.findings import Evidence, Finding
from ..core.findings import Severity as S
from .base import AdapterContext, AdapterResult, ToolAdapter, note_identical_copies, unique_targets

ELF_MACHINES = {"EM_ARM", "EM_AARCH64", "EM_X86_64", "EM_386", "EM_MIPS", "EM_PPC", "EM_PPC64", "EM_RISCV"}
RISK_RULES = {
    # name: (severity, classification, explanation, cwe)
    "gets": (S.high, C.detected, "gets() cannot bound its input; any reachable call is a stack overflow risk", "CWE-242"),
    "system": (S.medium, C.suspicious, "executes a shell command; review for command injection", "CWE-78"),
    "popen": (S.medium, C.suspicious, "executes a shell command; review for command injection", "CWE-78"),
    "strcpy": (S.low, C.suspicious, "unbounded string copy", "CWE-120"),
    "strcat": (S.low, C.suspicious, "unbounded string concatenation", "CWE-120"),
    "sprintf": (S.low, C.suspicious, "unbounded formatted write", "CWE-120"),
    "vsprintf": (S.low, C.suspicious, "unbounded formatted write", "CWE-120"),
    "scanf": (S.low, C.suspicious, "unbounded input parsing without width specifiers", "CWE-120"),
    "sscanf": (S.low, C.suspicious, "unbounded input parsing without width specifiers", "CWE-120"),
    "alloca": (S.low, C.suspicious, "stack allocation of caller-controlled size", "CWE-770"),
    "mktemp": (S.low, C.suspicious, "predictable temporary file names", "CWE-377"),
    "tmpnam": (S.low, C.suspicious, "predictable temporary file names", "CWE-377"),
    "rand": (S.info, C.info, "non-cryptographic PRNG (only a problem if used for security)", "CWE-338"),
}


class GhidraAdapter(ToolAdapter):
    name = "ghidra"
    display_name = "Ghidra headless (function analysis)"
    homepage = "https://ghidra-sre.org/"
    inputs = "ELF binaries (all Ghidra-supported architectures) and raw ARM Cortex-M images with a known load address"

    def enabled(self) -> bool:
        return self.settings.ghidra_enabled

    def status(self):
        runner = get_runner(self.settings)
        caps = runner.capabilities()
        img = self.settings.ghidra_image
        if not caps.get("docker") and not caps.get("broker"):
            return self._status(False, "Docker / the sandbox broker is not available to run Ghidra headless.")
        if not caps.get("images", {}).get(img):
            return self._status(False, f"Ghidra image '{img}' is not present. Run 'docker pull {img}'.",
                                mode=runner.kind)
        return self._status(True, f"Ghidra headless from image {img} via {runner.kind}", mode=runner.kind)

    def plan(self, ctx: AdapterContext):
        cands = []
        for a in ctx.manifest.get("extraction", {}).get("artifacts", []):
            elf = a.get("elf")
            if a.get("format") == "elf" and elf and elf.get("machine") in ELF_MACHINES \
                    and not elf.get("is_kernel_module"):
                score = 10 if a.get("category") in ("executable", "firmware_image") else 2
                if "busybox" in a["name"]:
                    score -= 20
                cands.append((score, a["size"], {"artifact": a, "raw": None}))
            elif a.get("format") == "cortexm_raw" and not a.get("details", {}).get("derived_from_elf") \
                    and a.get("details", {}).get("identical_to") is None:
                # (images derived from an ELF, or identical to one, are covered by analysing the ELF itself)
                base = a.get("details", {}).get("flash_base")
                if base:
                    cands.append((8, a["size"], {"artifact": a, "raw": {"processor": "ARM:LE:32:Cortex",
                                                                          "base": base}}))
        if not cands:
            return [], "no ELF binaries or raw Cortex-M images with a known load address"
        cands.sort(key=lambda c: (-c[0], -c[1]))
        targets = unique_targets(cands)
        n = self.settings.ghidra_max_binaries
        same = len(cands) - len(targets)
        return targets[:n], (f"{len(targets)} candidates" + (f" ({same} identical copies merged)" if same else "")
                             + f", analysing top {n}")

    def run(self, ctx: AdapterContext, targets: list) -> AdapterResult:
        out_dir = ctx.tool_dir(self.name)
        runner = get_runner(self.settings)
        findings: list[Finding] = []
        summaries = []
        failures = 0
        for i, t in enumerate(targets):
            a = t["artifact"]
            out = out_dir / f"functions_{i}.json"
            ctx.log(f"Ghidra: analysing {a['display_path']} ({i + 1}/{len(targets)})"
                    + (f" as raw {t['raw']['processor']} @ {t['raw']['base']}" if t["raw"] else ""))
            params = {"target": ctx.container_path(a), "out": ctx.container_path_of(out),
                      "analysis_timeout": max(60, self.settings.ghidra_timeout_s - 120)}
            if t["raw"]:
                params["raw"] = t["raw"]
            try:
                res = runner.run("ghidra", ctx.scan_id, params)
            except (JobError, JobRejected) as exc:
                failures += 1
                summaries.append({"binary": a["display_path"], "status": "failed", "error": str(exc)[:300]})
                continue
            ctx.write_file(out_dir / f"ghidra_{i}.log", (res.stdout + res.stderr)[-200_000:])
            try:
                raw = None if res.killed_reason else ctx.read_file(out, 256 * 1024 * 1024)
            except FileNotFoundError:
                raw = None
            except OSError as exc:  # a link or special file where the report should be
                failures += 1
                summaries.append({"binary": a["display_path"], "status": "failed", "error": f"unusable report: {exc}"})
                continue
            if raw is None:
                failures += 1
                err = res.killed_reason or _last_error(res.stdout + res.stderr) or f"exit code {res.exit_code}"
                summaries.append({"binary": a["display_path"], "status": "failed", "error": err[:400]})
                continue
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as exc:
                failures += 1
                summaries.append({"binary": a["display_path"], "status": "failed", "error": f"bad JSON: {exc}"})
                continue
            findings += note_identical_copies(normalize(data, a["display_path"], raw=bool(t["raw"])),
                                              t.get("duplicates"))
            summaries.append(summarize(data, a, t["raw"], res.duration_s))
        ok = len(targets) - failures
        msg = f"analysed {ok}/{len(targets)} binaries: " + "; ".join(
            f"{s['binary'].rsplit(' > ', 1)[-1]}: " + (f"{s['function_count']} functions" if s["status"] == "completed"
                                                      else f"failed ({s.get('error', '')[:100]})")
            for s in summaries)
        return AdapterResult("completed" if ok else "failed", msg, findings, str(out_dir), {"binaries": summaries})


def _last_error(log: str) -> str:
    lines = [ln for ln in log.splitlines() if "ERROR" in ln or "Exception" in ln]
    return lines[-1][:400] if lines else ""


def summarize(data: dict, art: dict, raw: dict | None, duration: float) -> dict:
    funcs = data.get("functions", [])
    named = sum(1 for f in funcs if not f["name"].startswith(("FUN_", "thunk_FUN_")))
    return {
        "binary": art["display_path"], "artifact_id": art["id"], "status": "completed", "duration_s": duration,
        "mode": "raw" if raw else "elf", "load_base": raw["base"] if raw else data.get("image_base"),
        "language": data.get("language"), "format": data.get("executable_format"),
        "function_count": data.get("function_count", 0), "named_functions": named,
        "instruction_count": data.get("instruction_count", 0), "external_count": data.get("external_count", 0),
        "risky_call_sites": {k: len(v) for k, v in (data.get("risky_calls") or {}).items()},
        "largest_functions": [{"name": f["name"], "entry": f["entry"], "size": f["size"]} for f in funcs[:10]],
        "most_called": [{"name": f["name"], "entry": f["entry"], "callers": f["callers"]}
                        for f in sorted(funcs, key=lambda f: -f.get("callers", 0))[:10]],
    }


def normalize(data: dict, binary: str, raw: bool = False) -> list[Finding]:
    out: list[Finding] = []
    for name, sites in sorted((data.get("risky_calls") or {}).items()):
        rule = RISK_RULES.get(name)
        if not rule or not sites:
            continue
        sev, cls, why, cwe = rule
        callers = Counter(s.get("function") or "?" for s in sites)
        out.append(Finding(
            title=f"[Ghidra] {name}() called from {len(sites)} site(s) in {len(callers)} function(s)",
            description=(f"Ghidra's call-reference analysis found calls to {name}(): {why}. This is a static "
                         "observation of API use; whether attacker-controlled data reaches these calls was not "
                         "analysed." + (" Symbols come from the binary's own symbol table." if not raw else "")),
            severity=sev, classification=cls, confidence=K.high if cls == C.detected else K.medium,
            source_tool="ghidra", rule_id=f"ghidra-call-{name}", affected_component=binary,
            remediation="Review each call site; replace with bounded alternatives (fgets, snprintf, strlcpy) or "
                        "validate inputs and lengths before the call.",
            evidence=[Evidence("address", f"call to {name} in {s.get('function') or '?'}", s.get("address"))
                      for s in sites[:25]],
            cwe=cwe, tags=["static-analysis", "function-level"]))
    return out
