"""FwAnalyzer adapter (https://github.com/cruise-automation/fwanalyzer).

Facts established from the upstream project and by running it:
* Input: a Linux filesystem image (ext2/3/4 via e2tools, SquashFS via
  squashfs-tools, UBIFS via ubi_reader, VFAT via mtools, cpio) or a
  directory (``dirfs``).  It does not understand MCU firmware such as PX4
  or ArduPilot flight controller images.
* Rules are a TOML config; output is a JSON report with ``offenders``,
  ``informational`` and ``data``.
* With stock (unpatched) e2tools the ext parser panics; upstream documents a
  patched e2tools fork.  When an image-level run fails we fall back to
  ``dirfs`` over our own extracted tree - in that mode file ownership/mode
  bits are NOT available (they are normalised during safe extraction), so
  permission checks are disabled and noted.
* The upstream repository is no longer actively developed.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from ..containers import JobError, JobRejected, get_runner
from ..core.findings import Classification as C
from ..core.findings import Confidence as K
from ..core.findings import Evidence, Finding
from ..core.findings import Severity as S
from .base import AdapterContext, AdapterResult, ToolAdapter, run_cmd

FS_TYPES = {"ext": "extfs", "squashfs": "squashfs", "fat": "vfatfs", "cpio": "cpiofs"}
BAD_FILES = [
    ("/etc/ssh/ssh_host_*_key", S.high, "SSH host private key shipped in image"),
    ("/etc/dropbear/dropbear_*_host_key", S.high, "Dropbear host key shipped in image"),
    ("**/id_rsa", S.high, "SSH private key shipped in image"),
    ("**/id_ecdsa", S.high, "SSH private key shipped in image"),
    ("**/id_ed25519", S.high, "SSH private key shipped in image"),
    ("**/authorized_keys", S.medium, "Pre-installed SSH authorized_keys"),
    ("**/.bash_history", S.low, "Shell history left in image"),
    ("**/.ash_history", S.low, "Shell history left in image"),
    ("/usr/sbin/telnetd", S.medium, "Telnet daemon present"),
    ("/usr/sbin/utelnetd", S.medium, "Telnet daemon present"),
    ("/usr/bin/gdbserver", S.medium, "Debugger server present"),
    ("/usr/bin/strace", S.low, "Debugging tool present"),
]


class FwAnalyzerAdapter(ToolAdapter):
    name = "fwanalyzer"
    display_name = "FwAnalyzer (Cruise)"
    homepage = "https://github.com/cruise-automation/fwanalyzer"
    inputs = "Linux filesystem images (ext2/3/4, SquashFS, UBIFS, VFAT, cpio) or extracted directories"

    def enabled(self) -> bool:
        return self.settings.fwanalyzer_enabled

    def _locate(self) -> tuple[str | None, str]:
        """('sandbox', detail) when the sandbox image bundles FwAnalyzer, ('local', ...) for a host binary."""
        if self.settings.fwanalyzer_bin:
            return "local", f"{self.settings.fwanalyzer_bin} on the worker host (NOT container-isolated)"
        if self.settings.sandbox_mode != "local":
            runner = get_runner(self.settings)
            caps = runner.capabilities()
            if caps.get("sandbox_tools", {}).get("fwanalyzer"):
                return "sandbox", (f"inside sandbox image {self.settings.sandbox_image} via {runner.kind} "
                                   "(no network, read-only)")
        local = shutil.which("fwanalyzer")
        if local:
            return "local", f"{local} on the worker host (NOT container-isolated)"
        return None, "'fwanalyzer' not found in the sandbox image or on PATH"

    def status(self):
        how, detail = self._locate()
        if how is None:
            return self._status(False, detail + ". Build the sandbox image (docker/sandbox.Dockerfile bundles "
                                       "FwAnalyzer) or install it with 'go install "
                                       "github.com/cruise-automation/fwanalyzer/cmd/fwanalyzer@latest'.")
        if how == "local":
            missing = [t for t in ("e2ls", "unsquashfs", "mcopy", "cpio") if not shutil.which(t)]
            if missing:
                detail += f"; missing helper tools: {', '.join(missing)}"
        return self._status(True, detail, mode=how)

    def plan(self, ctx: AdapterContext):
        man = ctx.manifest.get("extraction", {})
        arts = {a["id"]: a for a in man.get("artifacts", [])}
        targets = []
        for fs in man.get("filesystems", []):
            fstype = FS_TYPES.get(fs["type"])
            art = arts.get(fs.get("image_artifact", fs["artifact_id"]))
            if not art:
                continue
            try:  # 'root' and 'mode_image' come from the untrusted manifest: confined to the work directory
                fallback = ctx.artifact_path({"path": str(fs.get("root") or "")})
                image_path = ctx.artifact_path({"path": str(fs["mode_image"])}) if fs.get("mode_image") else None
            except ValueError:
                continue
            if fallback == ctx.work_dir.resolve() or str(fs.get("root")) == "<input>":
                continue
            if image_path and _looks_like_rootfs(fallback):
                # cpio written by the sandbox with the original modes/owners: permission rules work
                targets.append({"kind": "image", "fstype": "cpiofs", "artifact": art, "fallback_dir": fallback,
                                "image_path": image_path})
            elif fstype and _looks_like_rootfs(fallback):
                targets.append({"kind": "image", "fstype": fstype, "artifact": art, "fallback_dir": fallback})
            elif fs["type"] in ("tar", "zip", "romfs") and _looks_like_rootfs(fallback):
                targets.append({"kind": "dir", "fstype": "dirfs", "artifact": art, "fallback_dir": fallback})
            elif fs["type"] in ("cromfs", "romfs") and _looks_like_nuttx_etc(fallback):
                # NuttX ROM filesystem (PX4 /etc): FwAnalyzer cannot read CROMFS images itself, so it runs in
                # directory mode over the safely extracted tree with a PX4/NuttX rule set.
                targets.append({"kind": "dir", "fstype": "dirfs", "artifact": art, "fallback_dir": fallback,
                                "profile": "nuttx"})
        if not targets:
            return [], ("no Linux root filesystem or NuttX ROM filesystem was found (FwAnalyzer checks filesystem "
                        "contents; raw MCU code without an embedded filesystem is out of its scope)")
        return targets[:4], f"{len(targets)} filesystem(s)"

    def run(self, ctx: AdapterContext, targets: list) -> AdapterResult:
        out_dir = ctx.tool_dir(self.name)
        how, _ = self._locate()
        if how is None:
            return AdapterResult("unavailable", "fwanalyzer disappeared between status check and run")
        b = self.settings.fwanalyzer_bin or shutil.which("fwanalyzer") or "fwanalyzer"
        runner = (ctx, how)
        findings: list[Finding] = []
        runs = []
        for i, t in enumerate(targets):
            art = t["artifact"]
            report, mode, note = None, t["fstype"], None
            if t["kind"] == "image":
                image = t.get("image_path") or art  # validated in plan()
                report, err = self._run_one(runner, b, out_dir, i, t["fstype"], image, t["fallback_dir"],
                                            perms=True)
                if report is None:
                    note = f"image mode ({t['fstype']}) failed: {err}; fell back to dirfs on extracted tree"
                    ctx.log(f"fwanalyzer: {note}")
            if report is None:
                mode = "dirfs"
                report, err = self._run_one(runner, b, out_dir, i, "dirfs", t["fallback_dir"], t["fallback_dir"],
                                            perms=False, profile=t.get("profile", "linux"))
                if report is None:
                    runs.append({"target": art["display_path"], "status": "failed", "error": err, "note": note})
                    continue
            fs = normalize(report, art["display_path"], perms=(mode != "dirfs"), modes=_original_modes(ctx, t))
            findings += fs
            runs.append({"target": art["display_path"], "status": "completed", "mode": mode, "note": note,
                         "offenders": len(report.get("offenders", {}) or {}),
                         "informational": len(report.get("informational", {}) or {})})
        ok = sum(1 for r in runs if r["status"] == "completed")
        status = "completed" if ok else "failed"
        msg = f"analysed {ok}/{len(targets)} filesystem(s), {len(findings)} findings"
        notes = [r["note"] for r in runs if r.get("note")]
        if notes:
            msg += " - " + "; ".join(notes)
        if not ok:
            msg = "; ".join(r.get("error", "") for r in runs)[:800]
        return AdapterResult(status, msg, findings, str(out_dir), {"runs": runs, "execution": how})

    def _run_one(self, runner: tuple[AdapterContext, str], b: str, out_dir: Path, i: int, fstype: str,
                 target: Path | dict, tree: Path, perms: bool, profile: str = "linux") -> tuple[dict | None, str]:
        """``target`` is an artifact dict (filesystem image) or a directory (dirfs)."""
        ctx, how = runner
        cfg = ctx.write_file(out_dir / f"config_{i}_{fstype}.toml", build_config(fstype, tree, perms, profile))
        out = out_dir / f"report_{i}_{fstype}.json"
        out.unlink(missing_ok=True)
        if how == "sandbox":
            ctarget = ctx.container_path(target) if isinstance(target, dict) else ctx.container_path_of(target)
            try:
                res = get_runner(self.settings).run("fwanalyzer", ctx.scan_id, {
                    "config": ctx.container_path_of(cfg), "target": ctarget, "out": ctx.container_path_of(out)})
            except (JobError, JobRejected) as exc:
                return None, f"sandbox job failed: {exc}"
            rc, stdout, stderr = res.exit_code, res.stdout, res.stderr
            if res.killed_reason:
                return None, res.killed_reason
        else:
            host_target = ctx.artifact_path(target) if isinstance(target, dict) else target
            rc, stdout, stderr, _ = run_cmd([b, "-cfg", str(cfg), "-in", str(host_target), "-out", str(out)],
                                            timeout=self.settings.fwanalyzer_timeout_s)
        ctx.write_file(out_dir / f"stderr_{i}_{fstype}.log", (stdout + stderr)[-20000:])
        try:
            raw = ctx.read_file(out, 256 * 1024 * 1024) if rc == 0 else None
        except FileNotFoundError:
            raw = None
        except OSError as exc:
            return None, f"unusable report: {exc}"
        if raw is None:
            first = (stderr or stdout).strip().splitlines()[:1]
            return None, f"exit code {rc}: {first[0][:200] if first else 'no output'}"
        try:
            return json.loads(raw), ""
        except json.JSONDecodeError as exc:
            return None, f"invalid JSON report: {exc}"


def _original_modes(ctx: AdapterContext, t: dict) -> dict[str, tuple[int, bool]]:
    """Original modes of the filesystem's files (artifacts) and special directories (recorded by the sandbox)."""
    fs = next((f for f in ctx.manifest.get("extraction", {}).get("filesystems", [])
               if f.get("artifact_id") == t["artifact"].get("id")), {})
    out: dict[str, tuple[int, bool]] = {}
    for a in ctx.manifest.get("extraction", {}).get("artifacts", []):
        if a.get("parent_id") == fs.get("artifact_id") and isinstance(a.get("mode"), int):
            out[str(a.get("name"))] = (a["mode"], False)
    for d, m in (fs.get("special_dirs") or {}).items():
        if isinstance(m, int):
            out[str(d)] = (m, True)
    return out


def _looks_like_rootfs(d: Path) -> bool:
    return d.is_dir() and (d / "etc").is_dir() and any((d / x).is_dir() for x in ("bin", "sbin", "usr", "lib"))


def _toml_str(s: str) -> str:
    return json.dumps(s)  # JSON string escaping is valid TOML basic-string escaping


PX4_RULES = [
    ("cbrk", r"^\s*param\s+set(-default)?\s+CBRK_(IO_SAFETY\s+22027|SUPPLY_CHK\s+894281|USB_CHK\s+197848|"
             r"AIRSPD_CHK\s+162128)\b", "PX4 safety circuit breaker set to its disable value"),
    ("mavbcast", r"^\s*param\s+set(-default)?\s+MAV_BROADCAST\s+1\b", "PX4 MAVLink broadcast enabled"),
    ("apsafety", r"^\s*(ARMING_CHECK|BRD_SAFETYENABLE|BRD_SAFETY_DEFLT)[\s,=]+0(\.0+)?\s*$",
     "ArduPilot safety parameter disabled"),
]


def _looks_like_nuttx_etc(d: Path) -> bool:
    return d.is_dir() and ((d / "init.d").is_dir() or (d / "etc" / "init.d").is_dir())


def _nuttx_config(tree: Path) -> list[str]:
    lines = ["[GlobalConfig]", 'FsType = "dirfs"', "DigestImage = false", "",
             "[GlobalFileChecks]", "Suid = false", "WorldWrite = false",
             'BadFiles = ["**/*.pem", "**/*.key", "**/id_rsa", "**/id_ed25519"]', ""]
    n = 0
    for p in sorted(tree.rglob("*")):
        if not p.is_file() or p.stat().st_size == 0 or p.stat().st_size > 2 * 1024 * 1024:
            continue
        rel = "/" + str(p.relative_to(tree))
        if '"' in rel or "\\" in rel or p.suffix in (".xz", ".bin", ".json", ".gz"):
            continue
        for key, regex, desc in PX4_RULES:
            n += 1
            lines += [f'[FileContent."{key}_{n}"]', f"File = {_toml_str(rel)}", f"RegEx = {_toml_str(regex)}",
                      "RegExLineByLine = true", "Match = true", f"Desc = {_toml_str(desc)}", ""]
        if n > 3000:
            break
    return lines


def build_config(fstype: str, tree: Path, perms: bool, profile: str = "linux") -> str:
    if profile == "nuttx":
        return "\n".join(_nuttx_config(tree)) + "\n"
    lines = ["[GlobalConfig]", f"FsType = {_toml_str(fstype)}", "DigestImage = true", "",
             "[GlobalFileChecks]", f"Suid = {'true' if perms else 'false'}", "SuidAllowedList = []",
             f"WorldWrite = {'true' if perms else 'false'}",
             "BadFiles = [" + ", ".join(_toml_str(p) for p, _, _ in BAD_FILES) + "]", ""]
    # FileContent checks only for files that exist (a missing file is reported as an offender).
    if (tree / "etc/shadow").is_file():
        lines += ['[FileContent."shadow_empty_password"]', 'File = "/etc/shadow"', 'RegEx = "^[^:]+::"',
                  "RegExLineByLine = true", "Match = true", 'Desc = "account with empty password"', ""]
    if (tree / "etc/ssh/sshd_config").is_file():
        lines += ['[FileContent."sshd_permit_empty"]', 'File = "/etc/ssh/sshd_config"',
                  'RegEx = "^\\\\s*PermitEmptyPasswords\\\\s+yes"', "RegExLineByLine = true", "Match = true",
                  'Desc = "sshd allows empty passwords"', ""]
    if (tree / "etc/inittab").is_file():
        lines += ['[FileContent."inittab_telnetd"]', 'File = "/etc/inittab"', 'RegEx = "^[^#]*telnetd"',
                  "RegExLineByLine = true", "Match = true", 'Desc = "telnetd started from inittab"', ""]
    return "\n".join(lines) + "\n"


def _classify(msg: str, path: str, perms: bool) -> tuple[str, S, str, str]:
    """Return (rule, severity, title, cwe) for an FwAnalyzer offender message."""
    m = msg.lower()
    if "suid" in m:  # FwAnalyzer's Suid check covers setuid *and* setgid and labels both "File is SUID"
        return "fwa-suid", S.low, "setuid/setgid file not in allow-list", "CWE-250"
    if "worldwrite" in m:
        return "fwa-world-writable", S.medium, "World-writable file", "CWE-732"
    if "not allowed for pattern" in m or m.startswith("file not allowed"):
        for pat, sev, title in BAD_FILES:
            if pat in msg:
                return "fwa-bad-file", sev, title, "CWE-200"
        return "fwa-bad-file", S.medium, "Disallowed file present", "CWE-200"
    if "circuit breaker" in m:
        return "fwa-px4-cbrk", S.low, "PX4 safety circuit breaker disabled", "CWE-1188"
    if "mavlink broadcast" in m:
        return "fwa-px4-mav-broadcast", S.low, "PX4 MAVLink broadcast enabled", "CWE-319"
    if "ardupilot safety parameter" in m:
        return "fwa-ap-safety", S.low, "ArduPilot safety parameter disabled", "CWE-1188"
    if "empty password" in m:
        return "fwa-empty-password", S.critical if "line: root::" in msg else S.high, "Account with empty password", "CWE-258"
    if "permitemptypasswords" in m or "sshd allows empty" in m:
        return "fwa-sshd-empty", S.high, "sshd allows empty passwords", "CWE-258"
    if "telnetd" in m:
        return "fwa-telnetd", S.high, "telnetd started from inittab", "CWE-319"
    if "uid" in m or "gid" in m:
        return "fwa-ownership", S.low, "Unexpected file ownership", "CWE-732"
    return "fwa-offender", S.low, "FwAnalyzer policy violation", None


def _mode_note(mode: int | None, is_dir: bool) -> str:
    if mode is None:
        return ""
    bits = [b for b, v in (("setuid", 0o4000), ("setgid", 0o2000)) if mode & v]
    kind = "directory" if is_dir else "file"
    return f" [{'+'.join(bits) or 'no setuid/setgid bit'} {kind}, mode {mode & 0o7777:04o}]"


def normalize(report: dict, target: str, perms: bool, modes: dict[str, tuple[int, bool]] | None = None) -> list[Finding]:
    """``modes``: original mode (and whether it is a directory) per path, from the archive metadata."""
    out = []
    modes = modes or {}
    groups: dict[tuple[str, str], list[tuple[str, str]]] = {}
    meta: dict[str, tuple[S, str, str | None]] = {}
    for path, msgs in (report.get("offenders") or {}).items():
        for msg in msgs if isinstance(msgs, list) else [msgs]:
            rule, sev, title, cwe = _classify(str(msg), path, perms)
            groups.setdefault((rule, title), []).append((path, str(msg)))
            meta[rule + title] = (sev, title, cwe)
    for (rule, title), items in groups.items():
        sev, _, cwe = meta[rule + title]
        if rule == "fwa-empty-password" and any("line: root::" in m for _, m in items):
            sev = S.critical
        out.append(Finding(
            title=f"[FwAnalyzer] {title}" + (f" ({len(items)})" if len(items) > 1 else ""),
            description=("FwAnalyzer reported a policy violation for this filesystem. The rule set is generated by "
                         "Drone Firmware Analyzer (permission checks, disallowed files, insecure config content)."
                         + ("" if perms else " Run in directory mode: file ownership/permissions were not available.")),
            severity=sev, classification=C.detected, confidence=K.high, source_tool="fwanalyzer", rule_id=rule,
            affected_component=target, remediation=_REMEDIATION.get(rule, "Review the offending files."),
            evidence=[Evidence("tool_output", (m + (_mode_note(*modes[p]) if rule == "fwa-suid" and p in modes
                                                    else ""))[:240], p) for p, m in items[:25]],
            cwe=cwe, tags=["policy"]))
    info = report.get("informational") or {}
    if info:
        out.append(Finding(
            title=f"[FwAnalyzer] Informational results ({len(info)} paths)",
            description="FwAnalyzer produced informational (non-enforcing) results.", severity=S.info,
            classification=C.info, confidence=K.high, source_tool="fwanalyzer", rule_id="fwa-informational",
            affected_component=target, remediation="No action required.",
            evidence=[Evidence("tool_output", "; ".join(map(str, v))[:240] if isinstance(v, list) else str(v)[:240], p)
                      for p, v in list(info.items())[:25]]))
    return out


_REMEDIATION = {
    "fwa-suid": "Remove the setuid bit where not strictly required.",
    "fwa-world-writable": "Remove world-write permissions in the image build.",
    "fwa-bad-file": "Remove the file from the production image; generate keys per device at first boot.",
    "fwa-empty-password": "Lock the account or provision a unique per-device password.",
    "fwa-sshd-empty": "Set PermitEmptyPasswords no.",
    "fwa-telnetd": "Remove telnetd from inittab; use SSH with key authentication.",
}
